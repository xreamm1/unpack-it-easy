use crate::language::tr;
use eframe::egui;
use qrcode::{Color, QrCode};
use serde::Deserialize;
#[derive(Deserialize)]
struct Wallet {
    coin: String,
    network: String,
    address: String,
}
pub struct About {
    pub open: bool,
    wallets: Vec<Wallet>,
    selected: usize,
    qr: Option<egui::TextureHandle>,
}
impl Default for About {
    fn default() -> Self {
        Self {
            open: false,
            wallets: serde_json::from_str(include_str!("../assets/donations.json"))
                .expect("embedded wallets"),
            selected: 0,
            qr: None,
        }
    }
}
pub fn qr_image(value: &str) -> Result<egui::ColorImage, String> {
    let code = QrCode::new(value.as_bytes()).map_err(|e| e.to_string())?;
    let border = 4;
    let size = code.width() + border * 2;
    let mut image = egui::ColorImage::new([size, size], egui::Color32::WHITE);
    for y in 0..code.width() {
        for x in 0..code.width() {
            if code[(x, y)] == Color::Dark {
                image[(x + border, y + border)] = egui::Color32::BLACK;
            }
        }
    }
    Ok(image)
}
impl About {
    pub fn show(&mut self, ctx: &egui::Context) {
        if !self.open {
            return;
        }
        egui::Window::new(tr("о программе"))
            .id(egui::Id::new("about-uie"))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(560.0)
            .resizable(false)
            .collapsible(false)
            .open(&mut self.open)
            .show(ctx, |ui| {
                ui.heading("Unpack It Easy");
                ui.label(format!("UIE {}", env!("CARGO_PKG_VERSION")));
                ui.label(tr("автор: xreamm1"));
                ui.label(tr(
                    "анализ бинарных файлов извлечение ресурсов и декомпиляция в одном интерфейсе",
                ));
                ui.weak(tr(
                    "оригинальный исходный код и полная эквивалентность не гарантируются",
                ));
                ui.horizontal(|ui| {
                    ui.hyperlink_to("GitHub", "https://github.com/xreamm1/unpack-it-easy");
                    ui.label("MIT · Rust / egui");
                });
                ui.separator();
                ui.heading(tr("поддержать разработку"));
                ui.label(tr(
                    "на развитие uie — поддержку новых форматов и исправление ошибок",
                ));
                ui.horizontal_wrapped(|ui| {
                    for (index, wallet) in self.wallets.iter().enumerate() {
                        if ui
                            .selectable_label(self.selected == index, &wallet.coin)
                            .clicked()
                        {
                            self.selected = index;
                            self.qr = None;
                        }
                    }
                });
                let wallet = &self.wallets[self.selected];
                ui.label(format!("{} · {}", wallet.coin, wallet.network));
                if wallet.address.is_empty() {
                    ui.add_space(12.0);
                    ui.label(tr("адрес скоро появится"));
                    ui.weak(tr("qr-код появится после добавления адреса"));
                    ui.add_enabled(false, egui::Button::new(tr("скопировать адрес")));
                    ui.add_space(12.0);
                } else {
                    ui.horizontal(|ui| {
                        if self.qr.is_none() {
                            if let Ok(image) = qr_image(&wallet.address) {
                                self.qr = Some(ctx.load_texture(
                                    "donation-qr",
                                    image,
                                    egui::TextureOptions::NEAREST,
                                ));
                            }
                        }
                        if let Some(qr) = &self.qr {
                            ui.image((qr.id(), egui::vec2(190.0, 190.0)));
                        }
                        ui.vertical(|ui| {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&wallet.address).monospace())
                                    .wrap(),
                            );
                            if ui.button(tr("скопировать адрес")).clicked() {
                                ctx.copy_text(wallet.address.clone());
                            }
                            ui.weak(tr("проверь валюту и сеть перед переводом"));
                        });
                    });
                }
            });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn donation_list_and_qr_are_real() {
        let about = About::default();
        assert_eq!(about.wallets.len(), 5);
        assert_eq!(
            about
                .wallets
                .iter()
                .filter(|w| !w.address.is_empty())
                .count(),
            5
        );
        let image = qr_image("test-address").unwrap();
        assert!(image.pixels.contains(&egui::Color32::BLACK));
        assert_eq!(image[(0, 0)], egui::Color32::WHITE);
    }
}
