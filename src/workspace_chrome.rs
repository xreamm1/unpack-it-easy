use crate::language::tr;
use eframe::egui::{self, Color32};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Open,
    Load,
    Save,
    SaveCode,
    Folder,
    Undo,
    Redo,
    Search,
    Rename,
    Rebuild,
    Stop,
    Graph,
    Stages,
    Report,
    Log,
    Project,
    Settings,
    Background,
    Compare,
    CompareBases,
    CachedBase,
    Symbols,
    Plugins,
    Debugger,
    Crash,
    Update,
    About,
    Offline,
    Bundle,
    Language,
    Palette,
    Hex,
    Recovery,
    Inspection,
    Reports,
    Dynamic,
}

const MENUS: &[(&str, &[(Action, &str)])] = &[
    (
        "файл",
        &[
            (Action::Open, "открыть файл"),
            (Action::Load, "загрузить базу"),
            (Action::CachedBase, "проверенная база"),
            (Action::Save, "сохранить базу"),
            (Action::SaveCode, "сохранить · ctrl+s"),
            (Action::Folder, "каталог результата"),
            (Action::Recovery, "восстановление черновиков"),
        ],
    ),
    (
        "правка",
        &[
            (Action::Undo, "отменить правку"),
            (Action::Redo, "повторить правку"),
            (Action::Search, "поиск по проекту"),
            (Action::Rename, "переименовать"),
        ],
    ),
    (
        "анализ",
        &[
            (Action::Rebuild, "декомпилировать заново"),
            (Action::Dynamic, "динамический анализ трассы"),
            (Action::Stop, "остановить"),
            (Action::Graph, "граф вызовов"),
            (Action::Stages, "этапы"),
            (Action::Report, "отчёт"),
        ],
    ),
    (
        "вид",
        &[
            (Action::Project, "панель проекта"),
            (Action::Log, "лог"),
            (Action::Background, "фон"),
            (Action::Language, "сменить язык"),
            (Action::Palette, "палитра команд"),
        ],
    ),
    (
        "инструменты",
        &[
            (Action::Compare, "сравнение файлов"),
            (Action::Hex, "hex редактор"),
            (Action::Inspection, "xref и структуры"),
            (Action::Reports, "экспорт отчётов и сравнение исходников"),
            (Action::CompareBases, "сравнить две базы"),
            (Action::Symbols, "экспорт символов x64dbg"),
            (Action::Plugins, "плагины"),
            (Action::Settings, "настройки"),
            (Action::Offline, "офлайн"),
            (Action::Bundle, "скачать офлайн-комплект"),
            (Action::Debugger, "x64dbg / x32dbg"),
            (Action::Crash, "помощник сбоев"),
        ],
    ),
    (
        "справка",
        &[
            (Action::Update, "проверить обновления"),
            (Action::About, "о программе"),
        ],
    ),
];

pub struct Chrome {
    pub project: bool,
    palette: bool,
    query: String,
}
impl Default for Chrome {
    fn default() -> Self {
        Self {
            project: true,
            palette: false,
            query: String::new(),
        }
    }
}
pub struct State<'a> {
    pub english: bool,
    pub avatar: egui::TextureId,
    pub busy: bool,
    pub output: bool,
    pub input: bool,
    pub undo: bool,
    pub redo: bool,
    pub offline: bool,
    pub name: &'a str,
}
impl State<'_> {
    fn allowed(&self, action: Action) -> bool {
        match action {
            Action::Stop => self.busy,
            Action::Save | Action::SaveCode | Action::Folder | Action::Symbols => {
                !self.busy && self.output
            }
            Action::Rebuild | Action::CachedBase => !self.busy && self.input,
            Action::Undo => !self.busy && self.undo,
            Action::Redo => !self.busy && self.redo,
            Action::Update => !self.offline,
            Action::Debugger => !self.busy && cfg!(windows),
            Action::Open
            | Action::Load
            | Action::Compare
            | Action::CompareBases
            | Action::Plugins
            | Action::Settings
            | Action::Bundle
            | Action::Offline => !self.busy,
            _ => true,
        }
    }
}
impl Chrome {
    pub fn show(&mut self, ctx: &egui::Context, state: State<'_>) -> Vec<Action> {
        let mut actions = Vec::new();
        if ctx.input_mut(|i| {
            i.consume_key(
                egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
                egui::Key::P,
            )
        }) {
            self.palette = true;
            self.query.clear();
        }
        egui::TopBottomPanel::top("workspace-menu")
            .exact_height(34.0)
            .frame(
                egui::Frame::none()
                    .fill(Color32::from_gray(31))
                    .inner_margin(egui::Margin::symmetric(8.0, 3.0)),
            )
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.spacing_mut().item_spacing.x = 12.0;
                    ui.image((state.avatar, egui::vec2(22.0, 22.0)));
                    for (name, items) in MENUS {
                        ui.menu_button(title(&tr(name)), |ui| {
                            ui.set_min_width(285.0);
                            ui.spacing_mut().item_spacing.y = 1.0;
                            for (index, (action, label)) in items.iter().enumerate() {
                                if index > 0
                                    && matches!(
                                        action,
                                        Action::Folder
                                            | Action::Search
                                            | Action::Graph
                                            | Action::Background
                                            | Action::Plugins
                                            | Action::Crash
                                    )
                                {
                                    ui.separator();
                                }
                                let shortcut = match action {
                                    Action::SaveCode => "Ctrl+S",
                                    Action::Undo => "Ctrl+Z",
                                    Action::Redo => "Ctrl+Shift+Z",
                                    Action::Rename => "F2",
                                    Action::Palette => "Ctrl+Shift+P",
                                    _ => "",
                                };
                                if ui
                                    .add_enabled(
                                        state.allowed(*action),
                                        egui::Button::new(title(&tr(label)))
                                            .shortcut_text(shortcut)
                                            .frame(false)
                                            .min_size(egui::vec2(275.0, 25.0)),
                                    )
                                    .clicked()
                                {
                                    actions.push(*action);
                                    ui.close_menu();
                                }
                            }
                        });
                    }
                    if state.busy && ui.button(tr("остановить")).clicked() {
                        actions.push(Action::Stop);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mut english = state.english;
                        egui::ComboBox::from_id_salt("toolbar-language")
                            .width(85.0)
                            .selected_text(if english { "English" } else { "русский" })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut english, false, "русский");
                                ui.selectable_value(&mut english, true, "English");
                            });
                        if english != state.english {
                            actions.push(Action::Language);
                        }
                        ui.label(
                            egui::RichText::new(state.name)
                                .size(12.0)
                                .color(Color32::from_gray(150)),
                        );
                    });
                });
            });
        if self.palette {
            let mut open = true;
            egui::Window::new(tr("палитра команд"))
                .id(egui::Id::new("command-palette"))
                .anchor(egui::Align2::CENTER_TOP, [0.0, 90.0])
                .default_width(500.0)
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.query)
                            .hint_text(tr("найти команду"))
                            .desired_width(f32::INFINITY),
                    );
                    if !ctx.wants_keyboard_input() {
                        response.request_focus();
                    }
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let needle = self.query.to_lowercase();
                    let mut first = true;
                    egui::ScrollArea::vertical()
                        .max_height(330.0)
                        .show(ui, |ui| {
                            for (menu, items) in MENUS {
                                for (action, label) in *items {
                                    if *action == Action::Palette {
                                        continue;
                                    }
                                    let text = format!("{}  /  {}", tr(menu), tr(label));
                                    if !text.to_lowercase().contains(&needle) {
                                        continue;
                                    }
                                    let enabled = state.allowed(*action);
                                    if ui
                                        .add_enabled(enabled, egui::Button::new(&text).frame(false))
                                        .clicked()
                                        || (enter && first && enabled)
                                    {
                                        actions.push(*action);
                                        self.palette = false;
                                    }
                                    if enabled {
                                        first = false;
                                    }
                                }
                            }
                        });
                    if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        self.palette = false;
                    }
                });
            self.palette &= open;
        }
        actions
    }
    pub fn open_palette(&mut self) {
        self.palette = true;
        self.query.clear();
    }
}
fn title(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}
