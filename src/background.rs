use eframe::{egui, egui_glow, glow};
use glow::HasContext;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub animated: bool,
    pub adaptive: bool,
    pub max_fps: u32,
    pub min_fps: u32,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            animated: true,
            adaptive: true,
            max_fps: 30,
            min_fps: 10,
        }
    }
}

#[derive(Default)]
struct Clock {
    previous: Option<f64>,
    elapsed: f32,
    running: bool,
}
impl Clock {
    fn advance(&mut self, now: f64, paused: bool) -> f32 {
        if !paused && self.running {
            if let Some(previous) = self.previous {
                self.elapsed += (now - previous).clamp(0.0, 0.1) as f32;
            }
        }
        self.previous = Some(now);
        self.running = !paused;
        self.elapsed
    }
}

fn frame_interval(config: &Config, active: bool, gpu_seconds: f64) -> f64 {
    let maximum = config.max_fps.clamp(1, 60);
    let minimum = config.min_fps.clamp(1, maximum);
    if !config.adaptive {
        return 1.0 / maximum as f64;
    }
    let fps = if active { maximum } else { minimum };
    // Keep this optional decoration below roughly ten percent of GPU time.
    (1.0 / fps as f64)
        .max(gpu_seconds * 10.0)
        .min(1.0 / minimum as f64)
}

fn remaining_interval(last_frame: Option<f64>, now: f64, interval: f64) -> f64 {
    last_frame.map_or(0.0, |last| (interval - (now - last)).max(0.0))
}

fn texture_size(width: i32, height: i32, hardware_limit: i32) -> Option<[i32; 2]> {
    if width <= 0 || height <= 0 || hardware_limit <= 0 {
        return None;
    }
    let w = (width as f64 / 2.0).ceil();
    let h = (height as f64 / 2.0).ceil();
    let limit = hardware_limit.min(4096) as f64;
    let scale = 1.0_f64
        .min(limit / w)
        .min(limit / h)
        .min((4_194_304.0 / (w * h)).sqrt());
    Some([
        (w * scale).floor().max(1.0) as i32,
        (h * scale).floor().max(1.0) as i32,
    ])
}

const VERTEX: &str = r#"#version 330 core
void main(){vec2 p=vec2(float((gl_VertexID<<1)&2),float(gl_VertexID&2));gl_Position=vec4(p*2.0-1.0,0.0,1.0);}
"#;
const FRAGMENT: &str = r#"#version 330 core
uniform vec2 resolution;
uniform float clock_time;
out vec4 output_color;
vec2 gradient(vec2 p) {
    vec2 h=vec2(dot(p,vec2(127.1,311.7)),dot(p,vec2(269.5,183.3)));
    return fract(sin(h)*43758.5453123)*2.0-1.0;
}
float field(vec2 p) {
    vec2 a=floor(p), b=fract(p), w=b*b*(3.0-2.0*b);
    float lo=mix(dot(gradient(a),b),dot(gradient(a+vec2(1.0,0.0)),b-vec2(1.0,0.0)),w.x);
    float hi=mix(dot(gradient(a+vec2(0.0,1.0)),b-vec2(0.0,1.0)),dot(gradient(a+vec2(1.0,1.0)),b-vec2(1.0,1.0)),w.x);
    return mix(lo,hi,w.y);
}
float layers(vec2 p) {
    float value=0.0, weight=1.0, frequency=3.0;
    for(int i=0;i<4;i++){value+=weight*abs(field(p*frequency));frequency*=3.0;weight*=0.3;}
    return value;
}
void main() {
    vec2 cell=floor(gl_FragCoord.xy);
    vec2 uv=(gl_FragCoord.xy/resolution-0.5)*vec2(resolution.x/resolution.y,1.0)/1.2;
    float t=clock_time*0.05;
    vec2 warp=vec2(layers(uv+t),layers(uv-t+3.7));
    float value=layers(uv+(uv+warp)*0.6-t);
    float threshold=(mod(cell.y,4.0)+0.5)/4.0;
    float level=clamp(floor(clamp(value*1.15,0.0,1.0)*3.0+threshold),0.0,3.0);
    float tone=0.102;
    if(level>2.5)tone=0.39;else if(level>1.5)tone=0.27;else if(level>0.5)tone=0.17;
    output_color=vec4(vec3(tone),1.0);
}
"#;
const UPSCALE: &str = r#"#version 330 core
uniform sampler2D image;
uniform vec2 target_origin;
uniform vec2 target_size;
out vec4 output_color;
void main(){
    vec2 uv=(gl_FragCoord.xy-target_origin)/target_size;
    ivec2 size=textureSize(image,0);
    output_color=texelFetch(image,clamp(ivec2(uv*vec2(size)),ivec2(0),size-1),0);
}
"#;

// The fallback uses only ordinary egui geometry, including on older GL contexts.
pub fn paint_disabled(ctx: &egui::Context) {
    ctx.layer_painter(egui::LayerId::background()).rect_filled(
        ctx.screen_rect(),
        0.0,
        egui::Color32::from_gray(26),
    );
}

pub fn paint_static(ctx: &egui::Context) {
    let rect = ctx.screen_rect();
    let mut mesh = egui::Mesh::default();
    let (columns, rows) = (48, 32);
    for y in 0..rows {
        for x in 0..columns {
            let u = x as f32 / columns as f32;
            let v = y as f32 / rows as f32;
            let wave = ((u * 11.0 + (v * 9.0).sin() * 1.4).sin() + (v * 13.0 - u * 5.0).cos())
                * 0.25
                + 0.5;
            let tone = [26, 43, 69, 99][(wave * 3.99).clamp(0.0, 3.0) as usize];
            mesh.add_colored_rect(
                egui::Rect::from_min_max(
                    egui::pos2(
                        rect.left() + u * rect.width(),
                        rect.top() + v * rect.height(),
                    ),
                    egui::pos2(
                        rect.left() + (x + 1) as f32 / columns as f32 * rect.width(),
                        rect.top() + (y + 1) as f32 / rows as f32 * rect.height(),
                    ),
                ),
                egui::Color32::from_gray(tone),
            );
        }
    }
    ctx.layer_painter(egui::LayerId::background())
        .add(egui::Shape::mesh(mesh));
}

struct Cache {
    clock: Clock,
    last_frame: Option<f64>,
    last_interaction: f64,
    size: [i32; 2],
    valid: bool,
    failed: bool,
    query_pending: bool,
    gpu_seconds: f64,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            clock: Clock::default(),
            last_frame: None,
            last_interaction: 0.0,
            size: [0, 0],
            valid: false,
            failed: false,
            query_pending: false,
            gpu_seconds: 0.0,
        }
    }
}

pub struct Background {
    program: glow::Program,
    upscale: glow::Program,
    vao: glow::VertexArray,
    texture: glow::Texture,
    framebuffer: glow::Framebuffer,
    query: Option<glow::Query>,
    resolution: Option<glow::UniformLocation>,
    time: Option<glow::UniformLocation>,
    image: Option<glow::UniformLocation>,
    target_origin: Option<glow::UniformLocation>,
    target_size: Option<glow::UniformLocation>,
    texture_limit: i32,
    cache: Mutex<Cache>,
}

unsafe fn program(gl: &glow::Context, fragment: &str) -> Result<glow::Program, String> {
    let program = gl.create_program()?;
    let mut shaders = Vec::new();
    for (kind, source) in [
        (glow::VERTEX_SHADER, VERTEX),
        (glow::FRAGMENT_SHADER, fragment),
    ] {
        let shader = match gl.create_shader(kind) {
            Ok(shader) => shader,
            Err(error) => {
                for shader in shaders {
                    gl.delete_shader(shader);
                }
                gl.delete_program(program);
                return Err(error);
            }
        };
        gl.shader_source(shader, source);
        gl.compile_shader(shader);
        if !gl.get_shader_compile_status(shader) {
            let error = gl.get_shader_info_log(shader);
            gl.delete_shader(shader);
            for shader in shaders {
                gl.delete_shader(shader);
            }
            gl.delete_program(program);
            return Err(error);
        }
        gl.attach_shader(program, shader);
        shaders.push(shader);
    }
    gl.link_program(program);
    for shader in shaders {
        gl.detach_shader(program, shader);
        gl.delete_shader(shader);
    }
    if !gl.get_program_link_status(program) {
        let error = gl.get_program_info_log(program);
        gl.delete_program(program);
        return Err(error);
    }
    Ok(program)
}

// Capture every state changed by the two passes; egui may have a non-default target.
struct GlState {
    framebuffer: Option<glow::Framebuffer>,
    viewport: [i32; 4],
    scissor_box: [i32; 4],
    enabled: [(u32, bool); 5],
    program: Option<glow::Program>,
    vao: Option<glow::VertexArray>,
    active_texture: u32,
    texture: Option<glow::Texture>,
}
impl GlState {
    unsafe fn capture(gl: &glow::Context) -> Self {
        let mut viewport = [0; 4];
        let mut scissor_box = [0; 4];
        gl.get_parameter_i32_slice(glow::VIEWPORT, &mut viewport);
        gl.get_parameter_i32_slice(glow::SCISSOR_BOX, &mut scissor_box);
        let active_texture = gl.get_parameter_i32(glow::ACTIVE_TEXTURE) as u32;
        gl.active_texture(glow::TEXTURE0);
        Self {
            framebuffer: gl.get_parameter_framebuffer(glow::DRAW_FRAMEBUFFER_BINDING),
            viewport,
            scissor_box,
            enabled: [
                glow::BLEND,
                glow::SCISSOR_TEST,
                glow::DEPTH_TEST,
                glow::CULL_FACE,
                glow::STENCIL_TEST,
            ]
            .map(|cap| (cap, gl.is_enabled(cap))),
            program: gl.get_parameter_program(glow::CURRENT_PROGRAM),
            vao: gl.get_parameter_vertex_array(glow::VERTEX_ARRAY_BINDING),
            active_texture,
            texture: gl.get_parameter_texture(glow::TEXTURE_BINDING_2D),
        }
    }
    unsafe fn restore(&self, gl: &glow::Context) {
        gl.bind_framebuffer(glow::DRAW_FRAMEBUFFER, self.framebuffer);
        gl.viewport(
            self.viewport[0],
            self.viewport[1],
            self.viewport[2],
            self.viewport[3],
        );
        gl.scissor(
            self.scissor_box[0],
            self.scissor_box[1],
            self.scissor_box[2],
            self.scissor_box[3],
        );
        for (cap, enabled) in self.enabled {
            if enabled {
                gl.enable(cap);
            } else {
                gl.disable(cap);
            }
        }
        gl.use_program(self.program);
        gl.bind_vertex_array(self.vao);
        gl.bind_texture(glow::TEXTURE_2D, self.texture);
        gl.active_texture(self.active_texture);
    }
}

impl Background {
    pub fn new(gl: &glow::Context) -> Result<Self, String> {
        let version = gl.version();
        if version.is_embedded || (version.major, version.minor) < (3, 3) {
            return Err(
                "Animated background requires desktop OpenGL 3.3; using static background".into(),
            );
        }
        unsafe {
            let program = program(gl, FRAGMENT)?;
            let upscale = match self::program(gl, UPSCALE) {
                Ok(value) => value,
                Err(error) => {
                    gl.delete_program(program);
                    return Err(error);
                }
            };
            let vao = match gl.create_vertex_array() {
                Ok(value) => value,
                Err(error) => {
                    gl.delete_program(upscale);
                    gl.delete_program(program);
                    return Err(error);
                }
            };
            let texture = match gl.create_texture() {
                Ok(value) => value,
                Err(error) => {
                    gl.delete_vertex_array(vao);
                    gl.delete_program(upscale);
                    gl.delete_program(program);
                    return Err(error);
                }
            };
            let framebuffer = match gl.create_framebuffer() {
                Ok(value) => value,
                Err(error) => {
                    gl.delete_texture(texture);
                    gl.delete_vertex_array(vao);
                    gl.delete_program(upscale);
                    gl.delete_program(program);
                    return Err(error);
                }
            };
            Ok(Self {
                resolution: gl.get_uniform_location(program, "resolution"),
                time: gl.get_uniform_location(program, "clock_time"),
                image: gl.get_uniform_location(upscale, "image"),
                target_origin: gl.get_uniform_location(upscale, "target_origin"),
                target_size: gl.get_uniform_location(upscale, "target_size"),
                program,
                upscale,
                vao,
                texture,
                framebuffer,
                query: gl.create_query().ok(),
                texture_limit: gl.get_parameter_i32(glow::MAX_TEXTURE_SIZE),
                cache: Mutex::new(Cache::default()),
            })
        }
    }

    pub fn paint(self: &Arc<Self>, ctx: &egui::Context, config: &Config) {
        let (now, minimized, focused, interacted) = ctx.input(|input| {
            (
                input.time,
                input.viewport().minimized.unwrap_or(false),
                input.focused,
                !input.events.is_empty() || input.pointer.any_down(),
            )
        });
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        let time = cache.clock.advance(now, minimized || !config.animated);
        if minimized {
            cache.last_frame = None;
            return;
        }
        if !config.animated {
            cache.last_frame = None;
            drop(cache);
            paint_disabled(ctx);
            return;
        }
        if cache.failed {
            cache.last_frame = None;
            drop(cache);
            paint_static(ctx);
            return;
        }
        if interacted {
            cache.last_interaction = now;
        }
        let active = focused && now - cache.last_interaction < 1.5;
        let interval = frame_interval(config, active, cache.gpu_seconds);
        let remaining = remaining_interval(cache.last_frame, now, interval);
        let due = remaining <= 0.000_001;
        ctx.request_repaint_after(Duration::from_secs_f64(if due {
            interval
        } else {
            remaining
        }));
        let needs_fallback = !cache.valid;
        drop(cache);
        // Cover the first allocation without adding a second fullscreen pass thereafter.
        if needs_fallback {
            paint_static(ctx);
        }
        let renderer = self.clone();
        ctx.layer_painter(egui::LayerId::background())
            .add(egui::PaintCallback {
                rect: ctx.screen_rect(),
                callback: Arc::new(egui_glow::CallbackFn::new(move |info, painter| {
                    let gl = painter.gl();
                    let viewport = info.viewport_in_pixels();
                    let Some(size) = texture_size(
                        viewport.width_px,
                        viewport.height_px,
                        renderer.texture_limit,
                    ) else {
                        return;
                    };
                    let mut cache = renderer
                        .cache
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    if cache.failed {
                        return;
                    }
                    unsafe {
                        let state = GlState::capture(gl);
                        for (cap, _) in state.enabled {
                            gl.disable(cap);
                        }
                        gl.bind_vertex_array(Some(renderer.vao));
                        if cache.query_pending {
                            if let Some(query) = renderer.query {
                                if gl.get_query_parameter_u32(query, glow::QUERY_RESULT_AVAILABLE)
                                    != 0
                                {
                                    let seconds = gl
                                        .get_query_parameter_u32(query, glow::QUERY_RESULT)
                                        as f64
                                        * 1e-9;
                                    cache.gpu_seconds = if cache.gpu_seconds == 0.0 {
                                        seconds
                                    } else {
                                        cache.gpu_seconds * 0.75 + seconds * 0.25
                                    };
                                    cache.query_pending = false;
                                }
                            }
                        }
                        if size != cache.size {
                            gl.bind_texture(glow::TEXTURE_2D, Some(renderer.texture));
                            gl.tex_parameter_i32(
                                glow::TEXTURE_2D,
                                glow::TEXTURE_MIN_FILTER,
                                glow::NEAREST as i32,
                            );
                            gl.tex_parameter_i32(
                                glow::TEXTURE_2D,
                                glow::TEXTURE_MAG_FILTER,
                                glow::NEAREST as i32,
                            );
                            gl.tex_parameter_i32(
                                glow::TEXTURE_2D,
                                glow::TEXTURE_WRAP_S,
                                glow::CLAMP_TO_EDGE as i32,
                            );
                            gl.tex_parameter_i32(
                                glow::TEXTURE_2D,
                                glow::TEXTURE_WRAP_T,
                                glow::CLAMP_TO_EDGE as i32,
                            );
                            gl.tex_image_2d(
                                glow::TEXTURE_2D,
                                0,
                                glow::RGBA8 as i32,
                                size[0],
                                size[1],
                                0,
                                glow::RGBA,
                                glow::UNSIGNED_BYTE,
                                None,
                            );
                            gl.bind_framebuffer(glow::DRAW_FRAMEBUFFER, Some(renderer.framebuffer));
                            gl.framebuffer_texture_2d(
                                glow::DRAW_FRAMEBUFFER,
                                glow::COLOR_ATTACHMENT0,
                                glow::TEXTURE_2D,
                                Some(renderer.texture),
                                0,
                            );
                            if gl.check_framebuffer_status(glow::DRAW_FRAMEBUFFER)
                                != glow::FRAMEBUFFER_COMPLETE
                            {
                                cache.failed = true;
                                state.restore(gl);
                                return;
                            }
                            cache.size = size;
                            cache.valid = false;
                        }
                        if due || !cache.valid {
                            gl.bind_framebuffer(glow::DRAW_FRAMEBUFFER, Some(renderer.framebuffer));
                            gl.viewport(0, 0, size[0], size[1]);
                            gl.use_program(Some(renderer.program));
                            gl.uniform_2_f32(
                                renderer.resolution.as_ref(),
                                size[0] as f32,
                                size[1] as f32,
                            );
                            gl.uniform_1_f32(renderer.time.as_ref(), time);
                            let timed = renderer.query.filter(|_| !cache.query_pending);
                            if let Some(query) = timed {
                                gl.begin_query(glow::TIME_ELAPSED, query);
                            }
                            gl.draw_arrays(glow::TRIANGLES, 0, 3);
                            if timed.is_some() {
                                gl.end_query(glow::TIME_ELAPSED);
                                cache.query_pending = true;
                            }
                            cache.last_frame = Some(now);
                            cache.valid = true;
                        }
                        gl.bind_framebuffer(glow::DRAW_FRAMEBUFFER, state.framebuffer);
                        gl.viewport(
                            viewport.left_px,
                            viewport.from_bottom_px,
                            viewport.width_px,
                            viewport.height_px,
                        );
                        // Respect egui's clip rectangle for the presentation pass.
                        gl.scissor(
                            state.scissor_box[0],
                            state.scissor_box[1],
                            state.scissor_box[2],
                            state.scissor_box[3],
                        );
                        if state.enabled[1].1 {
                            gl.enable(glow::SCISSOR_TEST);
                        }
                        gl.use_program(Some(renderer.upscale));
                        gl.bind_texture(glow::TEXTURE_2D, Some(renderer.texture));
                        gl.uniform_1_i32(renderer.image.as_ref(), 0);
                        gl.uniform_2_f32(
                            renderer.target_origin.as_ref(),
                            viewport.left_px as f32,
                            viewport.from_bottom_px as f32,
                        );
                        gl.uniform_2_f32(
                            renderer.target_size.as_ref(),
                            viewport.width_px as f32,
                            viewport.height_px as f32,
                        );
                        gl.draw_arrays(glow::TRIANGLES, 0, 3);
                        state.restore(gl);
                    }
                })),
            });
    }

    pub fn destroy(&self, gl: &glow::Context) {
        unsafe {
            if let Some(query) = self.query {
                gl.delete_query(query);
            }
            gl.delete_framebuffer(self.framebuffer);
            gl.delete_texture(self.texture);
            gl.delete_vertex_array(self.vao);
            gl.delete_program(self.upscale);
            gl.delete_program(self.program);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paused_clock_resumes_without_jump() {
        let mut clock = Clock::default();
        clock.advance(0.0, false);
        let before = clock.advance(0.05, false);
        assert!(before > 0.0);
        assert_eq!(clock.advance(5.0, true), before);
        assert_eq!(clock.advance(100.0, false), before);
        assert!((clock.advance(100.05, false) - before - 0.05).abs() < 0.001);
    }
    #[test]
    fn field_is_half_resolution_and_bounded() {
        assert_eq!(texture_size(1920, 1080, 16384), Some([960, 540]));
        assert_eq!(texture_size(1921, 1081, 16384), Some([961, 541]));
        assert_eq!(texture_size(0, 100, 4096), None);
        assert_eq!(texture_size(100, 100, 0), None);
        for (w, h) in [(i32::MAX, i32::MAX), (30000, 2), (7680, 4320)] {
            let [w, h] = texture_size(w, h, 2048).unwrap();
            assert!(w > 0 && h > 0 && w <= 2048 && h <= 2048);
            assert!(w as i64 * h as i64 <= 4_194_304);
        }
    }
    #[test]
    fn cadence_slows_for_idle_and_gpu_cost_and_bounds_bad_config() {
        let mut config = Config::default();
        assert_eq!(frame_interval(&config, true, 0.0), 1.0 / 30.0);
        assert_eq!(frame_interval(&config, false, 0.0), 0.1);
        assert!(frame_interval(&config, true, 0.007) > 1.0 / 30.0);
        config.adaptive = false;
        assert_eq!(frame_interval(&config, false, 1.0), 1.0 / 30.0);
        config.max_fps = 0;
        config.min_fps = u32::MAX;
        assert_eq!(frame_interval(&config, true, 0.0), 1.0);
    }
    #[test]
    fn unrelated_ui_redraw_keeps_cached_field_until_due() {
        assert_eq!(remaining_interval(None, 1.0, 0.1), 0.0);
        assert!(remaining_interval(Some(1.0), 1.01, 0.1) > 0.08);
        assert_eq!(remaining_interval(Some(1.0), 1.11, 0.1), 0.0);
    }

    #[test]
    fn old_settings_use_defaults() {
        let config: Config = serde_json::from_str("{}").unwrap();
        assert!(config.animated && config.adaptive);
        assert_eq!((config.max_fps, config.min_fps), (30, 10));
    }
}
