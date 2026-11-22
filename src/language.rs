use std::sync::atomic::{AtomicBool, Ordering};
static ENGLISH: AtomicBool = AtomicBool::new(false);
pub fn set(english: bool) {
    ENGLISH.store(english, Ordering::Relaxed);
}
pub fn tr(text: &str) -> String {
    translate(text, ENGLISH.load(Ordering::Relaxed))
}
fn translate(text: &str, english: bool) -> String {
    if !english {
        return text.into();
    }
    if let Some((_, translated)) = TRANSLATIONS.iter().find(|(original, _)| *original == text) {
        return (*translated).into();
    }
    if !text.chars().any(|c| ('а'..='я').contains(&c) || c == 'ё') {
        return text.into();
    }
    let mut result = text.to_owned();
    for (from, to) in TRANSLATIONS {
        let mut next = String::new();
        let mut last = 0;
        for (at, _) in result.match_indices(from) {
            let end = at + from.len();
            let before = result[..at].chars().next_back();
            let after = result[end..].chars().next();
            if before.is_some_and(char::is_alphabetic) || after.is_some_and(char::is_alphabetic) {
                continue;
            }
            next.push_str(&result[last..at]);
            next.push_str(to);
            last = end;
        }
        if last > 0 {
            next.push_str(&result[last..]);
            result = next;
        }
    }
    result
}

const TRANSLATIONS: &[(&str, &str)] = &[
    ("офлайн", "offline"),
    ("все версии python", "all python versions"),
    ("скачать офлайн-комплект", "download offline bundle"),
    ("офлайн-комплект готов", "offline bundle ready"),
    ("подготовка офлайн-комплекта", "preparing offline bundle"),
    (
        "движки и модели сохраняются в engines; все версии требуют несколько гигабайт",
        "engines and models are cached in engines; all versions require several gigabytes",
    ),
    (
        "автоматическая обработка завершена; подробности проверки — в отчётах проекта",
        "automatic processing complete; see project reports for verification details",
    ),
    (
        "не определён по встроенным сигнатурам",
        "not identified by built-in signatures",
    ),
    ("управление потоком", "control flow"),
    ("декомпиляция функций", "function decompilation"),
    (
        "энтропия и XREF обозначают кандидатов обработки данных; это не доказательство дешифратора",
        "entropy and XREFs identify data-processing candidates; they do not prove decryption",
    ),
    (
        "при первом использовании движки скачиваются автоматически; ручная настройка не требуется",
        "engines are prepared automatically on first use; no manual setup required",
    ),
    (
        "ручные правки сохранены; эквивалентность после редактирования не проверена",
        "manual edits saved; equivalence after editing is unverified",
    ),
    (
        "строковые совпадения не доказывают сетевую активность или внедрение",
        "static string matches do not prove network activity or process injection",
    ),
    (
        "переименование во всём файле; строки и комментарии сохраняются",
        "file-wide lexical rename; strings and comments are preserved",
    ),
    (
        "сохрани изменённые вкладки перед загрузкой нового файла",
        "save modified tabs before loading another file",
    ),
    (
        "загрузи файл — движок будет выбран автоматически",
        "drop or open a file — the engine is selected automatically",
    ),
    (
        "обработка завершена; код открыт в редакторе",
        "processing complete; code opened in editor",
    ),
    (
        "код появится здесь после декомпиляции",
        "decompiled code will appear here",
    ),
    (
        "сохранить изменения перед закрытием?",
        "save changes before closing?",
    ),
    (
        "файл больше лимита редактора 32 MiB",
        "file exceeds the 32 MiB editor limit",
    ),
    (
        "XREF к участку высокой энтропии",
        "XREF to high-entropy data",
    ),
    (
        "исходник для объекта не создан",
        "no source was emitted for this object",
    ),
    ("ограничение отчёта достигнуто", "report limit reached"),
    (
        "отчёт появится после анализа",
        "report will appear after analysis",
    ),
    (
        "извлечение / соседние модули",
        "extraction / related modules",
    ),
    ("продолжить редактирование", "continue editing"),
    ("пользовательские / nuitka", "user / nuitka"),
    ("строки и индикаторы (IOC)", "strings and indicators (IOC)"),
    ("сохранить базу и закрыть", "save project and close"),
    ("сигнатуры detect it easy", "detect it easy signatures"),
    ("рабочий поток остановлен", "worker stopped"),
    ("заголовки и архитектура", "headers and architecture"),
    ("инициализаторы констант", "constant initializers"),
    ("исключено CRT / обёрток", "filtered CRT / wrappers"),
    ("закрыть без сохранения", "close without saving"),
    ("декомпилировать заново", "decompile again"),
    ("инициализатор констант", "constant initializer"),
    ("несовпадающих объектов", "mismatching objects"),
    ("ошибка сохранения базы", "project save failed"),
    ("настройки не сохранены", "settings were not saved"),
    ("несовпадающие объекты", "mismatching objects"),
    ("сигнатуры не найдены", "no signatures found"),
    ("проверка результата", "result verification"),
    ("изменения сохранены", "changes saved"),
    ("скопировать SHA-256", "copy SHA-256"),
    ("каталог результата", "output folder"),
    ("включая все модули", "include all modules"),
    ("подготовка движков", "engine setup"),
    ("сохранить · ctrl+s", "save · ctrl+s"),
    ("неполный результат", "partial result"),
    ("несохранённый код", "unsaved code"),
    ("проверенная база", "verified project"),
    ("функции и классы", "functions and classes"),
    ("быстрый просмотр", "fast view"),
    ("требуют проверки", "require review"),
    ("скопировать лог", "copy log"),
    ("обработка файла", "file processing"),
    ("показать ошибки", "show errors"),
    ("найти индикатор", "filter indicators"),
    ("загрузить базу", "load project"),
    ("сохранить базу", "save project"),
    ("лог скопирован", "log copied"),
    ("файл не найден", "file not found"),
    ("база сохранена", "project saved"),
    ("редактор кода", "code editor"),
    ("редактировать", "edit"),
    ("XREF к данным", "data XREFs"),
    ("чтение файла…", "reading file…"),
    ("переименовать", "rename"),
    ("открыть файл", "open file"),
    ("экспорт лога", "export log"),
    ("лог сохранён", "log saved"),
    ("декомпиляция", "decompilation"),
    ("большой файл", "large file"),
    ("скопировать", "copy"),
    ("остановить", "stop"),
    ("остановка…", "stopping…"),
    ("не найдено", "not found"),
    ("старое имя", "old name"),
    ("мини-карта", "mini map"),
    ("исходники", "sources"),
    ("остальные", "other"),
    ("новое имя", "new name"),
    ("применить", "apply"),
    ("база UIE", "UIE project"),
    ("энтропия", "entropy"),
    ("функций", "functions"),
    ("проект", "project"),
    ("журнал", "log"),
    ("ошибок", "errors"),
    ("отмена", "cancel"),
    ("этапы", "stages"),
    ("отчёт", "report"),
    ("поиск", "search"),
    ("найти", "find"),
    ("строк", "lines"),
    ("байт", "bytes"),
    ("код", "code"),
    ("лог", "log"),
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_languages_translate_ui_text() {
        assert_eq!(translate("открыть файл", true), "open file");
        assert_eq!(translate("открыть файл", false), "открыть файл");
        assert_eq!(
            translate("несовпадающие объекты: 3", true),
            "mismatching objects: 3"
        );
    }
}
