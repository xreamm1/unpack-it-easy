use crate::{
    engine::Settings,
    language::tr,
    telemetry::Problem,
    workspace_tools::{Graph, Search},
};
use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};
enum ResultView {
    Search(Search),
    Graph(Graph),
    Compare(String),
    Plugins(Vec<crate::plugins::Plugin>),
}
pub struct Tools {
    pub open: bool,
    tab: usize,
    root: Option<PathBuf>,
    query: String,
    filter: String,
    search: Search,
    graph: Graph,
    selected: usize,
    comparison: String,
    message: String,
    plugins: Vec<crate::plugins::Plugin>,
    loaded_plugins: bool,
    receiver: Option<mpsc::Receiver<Result<ResultView, String>>>,
    cancel: Arc<AtomicBool>,
}
impl Default for Tools {
    fn default() -> Self {
        Self {
            open: false,
            tab: 0,
            root: None,
            query: String::new(),
            filter: String::new(),
            search: Search::default(),
            graph: Graph::default(),
            selected: 0,
            comparison: String::new(),
            message: String::new(),
            plugins: vec![],
            loaded_plugins: false,
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Drop for Tools {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl Tools {
    pub fn open_tab(&mut self, tab: usize) {
        self.tab = tab.min(5);
        self.open = true;
    }
    pub fn open_settings(&mut self) {
        self.tab = 3;
        self.open = true;
    }
    fn start(
        &mut self,
        work: impl FnOnce(Arc<AtomicBool>) -> Result<ResultView, String> + Send + 'static,
    ) {
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.message = tr("обработка…");
        thread::spawn(move || {
            let _ = tx.send(work(cancel));
        });
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        root: Option<PathBuf>,
        settings: &mut Settings,
        edited: Vec<(PathBuf, String)>,
    ) -> Option<Problem> {
        let ctx = ui.ctx().clone();
        if self.root != root {
            self.cancel.store(true, Ordering::Relaxed);
            self.receiver = None;
            self.root = root.clone();
            self.search = Search::default();
            self.graph = Graph::default();
        }
        if !self.open {
            return None;
        }
        if !self.loaded_plugins {
            self.loaded_plugins = true;
            self.start(|_| crate::plugins::list().map(ResultView::Plugins));
        }
        if let Some(value) = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(value) => Some(value),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("analysis utility stopped".into())),
            Err(_) => None,
        }) {
            self.receiver = None;
            self.message.clear();
            match value {
                Ok(ResultView::Search(value)) => self.search = value,
                Ok(ResultView::Graph(value)) => {
                    self.graph = value;
                    self.selected = 0;
                }
                Ok(ResultView::Compare(value)) => self.comparison = value,
                Ok(ResultView::Plugins(value)) => self.plugins = value,
                Err(error) => self.message = error,
            }
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let mut open = self.open;
        let mut jump = None;
        egui::Frame::none().fill(Color32::from_gray(24)).inner_margin(egui::Margin::same(20.0)).show(ui,|ui|{
            ui.set_min_size(ui.available_size());
            ui.horizontal(|ui|{
                ui.label(egui::RichText::new(tr("инструменты анализа")).size(18.0));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{if ui.button("×").on_hover_text(tr("закрыть вкладку")).clicked(){open=false;}});
            });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui|{
                ui.spacing_mut().item_spacing.x=8.0;
                for(index,label)in["поиск по проекту","граф вызовов","сравнение файлов","движки и ограничения","фон","оформление"].iter().enumerate(){
                    let selected=self.tab==index;
                    let response=ui.add(egui::Button::new(tr(label)).fill(Color32::from_gray(if selected{64}else{32})).stroke(egui::Stroke::new(1.0_f32,Color32::from_gray(if selected{140}else{55}))).min_size(egui::vec2(90.0,30.0)));
                    if response.clicked(){self.tab=index;}
                }
            });
            ui.add_space(18.0);
            let ready=self.receiver.is_none();
            if self.tab>=3{ui.set_max_width(720.0);}
            match self.tab {
                0=>{
                    ui.horizontal(|ui|{ui.text_edit_singleline(&mut self.query);if ui.add_enabled(ready&&root.is_some(),egui::Button::new(tr("найти"))).clicked(){
                        let root=root.clone().unwrap();let query=self.query.clone();self.start(move|cancel|crate::workspace_tools::search(&root,&query,&edited,&cancel).map(ResultView::Search));
                    }});
                    ui.weak(tr("поиск включает несохранённые правки открытых файлов"));
                    if self.search.truncated||self.search.skipped>0 {ui.label(format!("{} · skipped: {}",tr("результат ограничен"),self.search.skipped));}
                    egui::ScrollArea::vertical().max_height(450.0).show_rows(ui,22.0,self.search.hits.len(),|ui,rows|{for i in rows{
                        let hit=&self.search.hits[i];if ui.link(format!("{}:{}  {}",hit.file.display(),hit.line,hit.message)).clicked(){jump=Some(hit.clone());}
                    }});
                },
                1=>{
                    ui.horizontal(|ui|{if ui.add_enabled(ready&&root.is_some(),egui::Button::new(tr("построить граф"))).clicked(){let root=root.clone().unwrap();self.start(move|cancel|crate::workspace_tools::graph(&root,&cancel).map(ResultView::Graph));}
                        ui.text_edit_singleline(&mut self.filter);});
                    ui.weak(tr("статические вызовы — косвенные и динамические связи могут отсутствовать"));
                    if self.graph.truncated{ui.label(tr("результат ограничен"));}
                    egui::ScrollArea::vertical().max_height(90.0).show(ui,|ui|{
                        for(index,node)in self.graph.nodes.iter().enumerate().filter(|(_,n)|n.name.to_lowercase().contains(&self.filter.to_lowercase())).take(200){
                            if ui.selectable_label(self.selected==index,format!("{} · {}",node.name,node.key)).clicked(){self.selected=index;}
                        }
                    });
                    if let Some(value)=self.draw_graph(ui){jump=Some(value);}
                },
                2=>{
                    if ui.add_enabled(ready,egui::Button::new(tr("выбрать два файла"))).clicked(){
                        if let Some(paths)=rfd::FileDialog::new().pick_files(){
                            if paths.len()!=2 {self.message=tr("выбери ровно два файла");}else{self.start(move|_|{
                                let is_base=paths.iter().all(|p|crate::telemetry::is_base(p));
                                let value=if is_base{crate::project_diff::compare(&paths[0],&paths[1])?}else{crate::binary_compare::compare(&paths[0],&paths[1])?};
                                serde_json::to_string_pretty(&value).map(ResultView::Compare).map_err(|e|e.to_string())
                            });}
                        }
                    }
                    ui.weak(tr("exe сравниваются по байтам и секциям — базы uie также по восстановленным функциям"));
                    if !self.comparison.is_empty(){ui.horizontal(|ui|{
                        if ui.button(tr("скопировать отчёт")).clicked(){ui.ctx().copy_text(self.comparison.clone());}
                        if ui.button(tr("сохранить отчёт")).clicked(){if let Some(path)=rfd::FileDialog::new().add_filter("JSON",&["json"]).save_file(){if let Err(e)=std::fs::write(path,&self.comparison){self.message=e.to_string();}}}
                    });}
                    egui::ScrollArea::both().max_height(430.0).show(ui,|ui|{ui.monospace(&self.comparison);});
                },
                3=>{
                    let mut options_changed=ui.checkbox(&mut settings.all_modules,tr("включая все модули")).changed();
                    options_changed|=ui.checkbox(&mut settings.lazy_native,tr("ленивая декомпиляция native")).changed();
                    options_changed|=ui.checkbox(&mut settings.force_rebuild,tr("декомпилировать заново без кэша")).changed();
                    options_changed|=ui.checkbox(&mut settings.autosave,tr("автосохранение черновиков")).changed();
                    if options_changed{if let Err(e)=settings.save(){self.message=e;}}
                    ui.separator();
                    let before=settings.decompiler_plugin.clone();
                    let selected_engine=settings.decompiler_plugin.clone().unwrap_or_else(||tr("автоматический выбор"));
                    egui::ComboBox::from_id_salt("external-decompiler").selected_text(selected_engine).show_ui(ui,|ui|{
                        ui.selectable_value(&mut settings.decompiler_plugin,None,tr("автоматический выбор"));
                        for plugin in &self.plugins {ui.selectable_value(&mut settings.decompiler_plugin,Some(plugin.id.clone()),&plugin.name);}
                    });
                    if ready&&ui.button(tr("обновить список плагинов")).clicked(){self.start(|_|crate::plugins::list().map(ResultView::Plugins));}
                    ui.weak(tr("плагины запускают доверенные внешние программы — это не изоляция файлов и сети"));
                    ui.label(crate::runtime::root().join("plugins").display().to_string());
                    let mut changed=before!=settings.decompiler_plugin;
                    changed|=ui.add_enabled(crate::process_limits::supported(),egui::Checkbox::new(&mut settings.analysis_limits.enabled,tr("ограничивать процессы анализа"))).changed();
                    ui.horizontal(|ui|{ui.label(tr("память миб"));changed|=ui.add(egui::DragValue::new(&mut settings.analysis_limits.memory_mib).range(128..=65536)).changed();
                        ui.label(tr("процессы"));changed|=ui.add(egui::DragValue::new(&mut settings.analysis_limits.active_process_limit).range(1..=128)).changed();});
                    if !crate::process_limits::supported(){ui.weak(tr("ограничения job object доступны только в windows"));}
                    if changed{if let Err(e)=settings.save(){self.message=e;}}
                }
                4=>{
                    ui.label(egui::RichText::new(tr("фон")).size(16.0).strong());
                    ui.add_space(12.0);
                    let mut changed=false;
                    if ui.button(tr(if settings.background.animated{"отключить фон"}else{"включить фон"})).clicked(){
                        settings.background.animated= !settings.background.animated;
                        changed=true;
                    }
                    ui.add_space(14.0);
                    changed|=ui.checkbox(&mut settings.background.adaptive,tr("адаптивная частота")).changed();
                    changed|=ui.add(egui::Slider::new(&mut settings.background.max_fps,10..=60).text(tr("максимум кадров в секунду"))).changed();
                    changed|=ui.add(egui::Slider::new(&mut settings.background.min_fps,1..=30).text(tr("минимум кадров в секунду"))).changed();
                    settings.background.min_fps=settings.background.min_fps.min(settings.background.max_fps);
                    ui.weak(tr("без поддержки шейдера используется статический фон"));
                    if changed{if let Err(e)=settings.save(){self.message=e;}}
                }
                _=>{if settings.theme.show(ui){if let Err(e)=settings.save(){self.message=e;}}}
            }
            if self.receiver.is_some(){ui.spinner();if ui.button(tr("отменить")).clicked(){self.cancel.store(true,Ordering::Relaxed);}}
            if !self.message.is_empty(){ui.label(&self.message);}
        });
        self.open = open;
        if !open {
            self.cancel.store(true, Ordering::Relaxed);
        }
        jump
    }
    fn draw_graph(&self, ui: &mut egui::Ui) -> Option<Problem> {
        let node = self.graph.nodes.get(self.selected)?;
        let incoming: Vec<_> = self
            .graph
            .edges
            .iter()
            .filter(|(_, to)| *to == self.selected)
            .map(|(from, _)| *from)
            .filter(|id| *id != self.selected)
            .take(12)
            .collect();
        let outgoing: Vec<_> = self
            .graph
            .edges
            .iter()
            .filter(|(from, _)| *from == self.selected)
            .map(|(_, to)| *to)
            .filter(|id| *id != self.selected)
            .take(12)
            .collect();
        let height = (incoming.len().max(outgoing.len()).max(1) as f32 * 40.0 + 40.0).max(180.0);
        ui.weak(tr(
            "показано до 12 связей с каждой стороны — клик открывает код",
        ));
        let mut jump = None;
        egui::ScrollArea::both().max_height(390.0).show(ui, |ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::new(820.0, height), egui::Sense::hover());
            let center = Rect::from_center_size(
                rect.min + Vec2::new(410.0, height / 2.0),
                Vec2::new(220.0, 30.0),
            );
            let paint = ui.painter();
            let stroke = Stroke::new(1.0_f32, Color32::from_gray(170));
            if self.graph.edges.contains(&(self.selected, self.selected)) {
                paint.text(
                    center.center_top() - Vec2::new(0.0, 14.0),
                    egui::Align2::CENTER_CENTER,
                    tr("рекурсивный вызов"),
                    egui::FontId::monospace(12.0),
                    Color32::WHITE,
                );
            }
            let mut nodes = vec![(self.selected, center)];
            for (list, x, is_in) in [(&incoming, 125.0, true), (&outgoing, 695.0, false)] {
                for (index, id) in list.iter().enumerate() {
                    let r = Rect::from_center_size(
                        rect.min + Vec2::new(x, 30.0 + index as f32 * 40.0),
                        Vec2::new(220.0, 30.0),
                    );
                    let (a, b) = if is_in {
                        (r.right_center(), center.left_center())
                    } else {
                        (center.right_center(), r.left_center())
                    };
                    paint.arrow(a, b - a, stroke);
                    nodes.push((*id, r));
                }
            }
            for (id, r) in nodes {
                let n = &self.graph.nodes[id];
                let response =
                    ui.interact(r, ui.id().with(("graph-node", id)), egui::Sense::click());
                paint.rect_filled(
                    r,
                    3.0,
                    Color32::from_gray(if response.hovered() { 65 } else { 35 }),
                );
                paint.rect_stroke(r, 3.0, stroke);
                paint.text(
                    Pos2::new(r.center().x, r.center().y),
                    egui::Align2::CENTER_CENTER,
                    n.name.chars().take(28).collect::<String>(),
                    egui::FontId::monospace(12.0),
                    Color32::WHITE,
                );
                if response.clicked() {
                    jump = Some(n.location.clone());
                }
            }
            ui.label(format!(
                "{} · {} nodes / {} edges",
                node.key,
                self.graph.nodes.len(),
                self.graph.edges.len()
            ));
        });
        jump
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tools_tab_renders_without_a_project() {
        let ctx = egui::Context::default();
        let mut settings = Settings::default();
        let mut tools = Tools::default();
        tools.open = true;
        tools.loaded_plugins = true;
        for tab in 0..5 {
            tools.tab = tab;
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    assert!(tools.show(ui, None, &mut settings, Vec::new()).is_none());
                });
            });
        }
    }

    #[test]
    fn settings_round_trip_keeps_limits_engine_and_background() {
        let mut settings = Settings::default();
        settings.analysis_limits.memory_mib = 4096;
        settings.analysis_limits.active_process_limit = 8;
        settings.decompiler_plugin = Some("local-engine".into());
        settings.background.animated = false;
        settings.background.max_fps = 24;
        let decoded: Settings =
            serde_json::from_slice(&serde_json::to_vec(&settings).unwrap()).unwrap();
        assert_eq!(decoded.analysis_limits.memory_mib, 4096);
        assert_eq!(decoded.analysis_limits.active_process_limit, 8);
        assert_eq!(decoded.decompiler_plugin.as_deref(), Some("local-engine"));
        assert!(!decoded.background.animated);
        assert_eq!(decoded.background.max_fps, 24);
        let old: Settings = serde_json::from_str("{\"english\":false}").unwrap();
        assert!(!old.english);
        assert!(old.background.animated);
        assert!(old.decompiler_plugin.is_none());
    }
}
