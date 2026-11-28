use crate::language::tr;
use eframe::egui::{self, Color32, Stroke};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Theme {
    pub text: u8,
    pub surface: u8,
    pub selection: u8,
    pub code: u8,
}
impl Default for Theme {
    fn default() -> Self {
        Self {
            text: 255,
            surface: 46,
            selection: 70,
            code: 0,
        }
    }
}
impl Theme {
    pub fn apply(&self, ctx: &egui::Context) {
        ctx.set_theme(egui::Theme::Dark);
        ctx.style_mut(|style| {
            let text = Color32::from_gray(self.text.max(150));
            style.visuals.override_text_color = Some(text);
            style.visuals.hyperlink_color = text;
            style.visuals.selection.bg_fill = Color32::from_gray(self.selection.clamp(35, 110));
            style.visuals.widgets.inactive.bg_fill = Color32::from_gray(self.surface.clamp(20, 80));
            style.visuals.widgets.inactive.weak_bg_fill = style.visuals.widgets.inactive.bg_fill;
            style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, text);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
            style.spacing.interact_size.y = 28.0;
            style.spacing.item_spacing = egui::vec2(10.0, 9.0);
            style.visuals.widgets.inactive.bg_stroke = Stroke::NONE;
            style.visuals.widgets.hovered.bg_fill = Color32::from_gray(72);
            style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_gray(220));
        });
    }
    pub fn editor_color(&self) -> Color32 {
        Color32::from_gray(self.code.min(30))
    }
    pub fn show(&mut self, ui: &mut egui::Ui) -> bool {
        ui.label(tr("настройки монохромной темы"));
        let mut changed = ui
            .add(egui::Slider::new(&mut self.text, 150..=255).text(tr("яркость текста")))
            .changed();
        changed |= ui
            .add(egui::Slider::new(&mut self.surface, 20..=80).text(tr("яркость кнопок")))
            .changed();
        changed |= ui
            .add(egui::Slider::new(&mut self.selection, 35..=110).text(tr("яркость выделения")))
            .changed();
        changed |= ui
            .add(egui::Slider::new(&mut self.code, 0..=30).text(tr("фон редактора")))
            .changed();
        if ui.button(tr("сбросить тему")).clicked() {
            *self = Self::default();
            changed = true;
        }
        changed
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_and_invalid_settings_keep_readable_bounds() {
        let mut theme: Theme = serde_json::from_str("{}").unwrap();
        assert_eq!(theme.code, 0);
        theme.text = 0;
        theme.surface = 255;
        theme.code = 255;
        let ctx = egui::Context::default();
        ctx.set_theme(egui::Theme::Light);
        theme.apply(&ctx);
        assert!(ctx.style().visuals.dark_mode);
        assert_eq!(
            ctx.style().visuals.override_text_color,
            Some(Color32::from_gray(150))
        );
        assert_eq!(theme.editor_color(), Color32::from_gray(30));
    }
}
