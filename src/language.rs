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
        if let Some((original, _)) = TRANSLATIONS
            .iter()
            .find(|(_, translated)| *translated == text)
        {
            return (*original).into();
        }
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
    ("настройки", "settings"),
    ("декомпилировать заново без кэша", "decompile again without cache"),
    ("инструменты анализа", "analysis tools"),
    ("поиск по проекту", "project search"),
    ("граф вызовов", "call graph"),
    ("сравнение файлов", "file comparison"),
    ("движки и ограничения", "engines and limits"),
    ("обработка…", "processing…"),
    ("поиск включает несохранённые правки открытых файлов", "search includes unsaved edits in open files"),
    ("результат ограничен", "result is bounded"),
    ("построить граф", "build graph"),
    ("статические вызовы — косвенные и динамические связи могут отсутствовать", "static calls; indirect and dynamic edges may be missing"),
    ("показано до 12 связей с каждой стороны — клик открывает код", "up to 12 edges per side; click opens code"),
    ("рекурсивный вызов", "recursive call"),
    ("выбрать два файла", "select two files"),
    ("выбери ровно два файла", "select exactly two files"),
    ("exe сравниваются по байтам и секциям — базы uie также по восстановленным функциям", "executables: bytes and sections; UIE bases: recovered functions as well"),
    ("скопировать отчёт", "copy report"),
    ("сохранить отчёт", "save report"),
    ("автоматический выбор", "automatic selection"),
    ("обновить список плагинов", "refresh plugins"),
    ("плагины запускают доверенные внешние программы — это не изоляция файлов и сети", "plugins run trusted external programs; filesystem and network access are not isolated"),
    ("ограничивать процессы анализа", "limit analysis processes"),
    ("память миб", "memory MiB"),
    ("процессы", "processes"),
    ("ограничения job object доступны только в windows", "job object limits are available on Windows only"),
    ("анимация фона", "background animation"),
    ("отключить фон", "disable background"),
    ("включить фон", "enable background"),
    ("отменить правку", "undo"),
    ("повторить правку", "redo"),
    ("файл", "file"),
    ("правка", "edit"),
    ("анализ", "analysis"),
    ("динамический анализ трассы", "dynamic trace analysis"),
    ("вид", "view"),
    ("инструменты", "tools"),
    ("справка", "help"),
    ("панель проекта", "project panel"),
    ("сменить язык", "switch language"),
    ("палитра команд", "command palette"),
    ("найти команду", "find a command"),
    ("плагины", "plugins"),
    ("готово", "ready"),
    ("онлайн", "online"),
    ("сведения", "details"),
    ("ещё", "more"),
    ("помощник сбоев", "crash assistant"),
    ("hex редактор", "hex editor"),
    ("xref и структуры", "xref and types"),
    ("экспорт отчётов и сравнение исходников", "report export and source comparison"),
    ("автосохранение", "autosave"),
    ("сохранение исходников", "saving source files"),
    ("оформление", "appearance"),
    ("настройки монохромной темы", "monochrome theme settings"),
    ("яркость текста", "text brightness"),
    ("яркость кнопок", "button brightness"),
    ("яркость выделения", "selection brightness"),
    ("фон редактора", "editor background"),
    ("сбросить тему", "reset theme"),
    ("автосохранение черновиков", "autosave drafts"),
    ("восстановление черновиков", "recover drafts"),
    ("восстановление открывает текст в редакторе исходные файлы не меняются", "recovery opens text in the editor without changing original files"),
    ("исходник изменён или отсутствует", "original changed or missing"),
    ("восстановить", "restore"),
    ("удалить черновик", "discard draft"),
    ("черновик восстановлен сохранение создаст новую копию", "draft restored; saving creates a new copy"),
    ("исходник изменился выбери другой файл", "choose a different file for the recovered copy"),
    ("закрыть вкладку", "close tab"),
    ("сначала сохрани изменения файла", "save the file before closing this tab"),
    ("адаптивная частота", "adaptive refresh"),
    ("максимум кадров в секунду", "maximum frames per second"),
    ("минимум кадров в секунду", "minimum frames per second"),
    ("без поддержки шейдера используется статический фон", "a static background is used without shader support"),
    ("фон", "background"),
    ("декомпиляция Android через JADX", "decompiling Android with JADX"),
    ("apk содержит bytecode и ресурсы; нативные JNI библиотеки требуют отдельного анализа", "APK contains bytecode and resources; native JNI libraries require separate analysis"),
    ("метаданные методов не содержат python-байткод", "method metadata does not contain Python bytecode"),
    ("точки входа модулей nuitka", "Nuitka module entry points"),
    ("точка входа нативного модуля", "native module entry point"),
    ("python имена из traceback", "Python names from traceback metadata"),
    ("python имя из traceback", "Python name from traceback metadata"),
    ("восстановлены имена и места ошибок — тела остаются псевдокодом", "names and error sites recovered; bodies remain native pseudocode"),
    ("константы и кандидаты строк", "constants and string candidates"),
    ("статические кандидаты — выполнение не наблюдалось", "static candidates; execution was not observed"),
    ("достигнут лимит анализа", "analysis budget reached"),
    ("перейти к содержащей функции", "jump to containing function"),
    ("статический кандидат", "static candidate"),
    ("строка слишком длинная для встроенного редактирования", "line is too long for inline editing"),
("что нового","what is new"),
("описание обновления не опубликовано","no release notes were published"),
("полный changelog на github","full changelog on GitHub"),
("подготовка отладчика","preparing debugger"),
("открытие образца в отладчике запускает его процесс","opening a sample in the debugger starts its process"),
("открыть пустой отладчик","open empty debugger"),
("запустить образец под отладчиком","start sample under debugger"),
("на развитие uie — поддержку новых форматов и исправление ошибок","for UIE development — new formats and bug fixes"),
("см.","see"),

("строковые признаки компилятора — эвристика, не доказательство; исходный код может восстановиться частично","compiler string markers are heuristic evidence; source recovery may be partial"),
("открыт сохранённый проект; SHA256 образца и исходников совпадает; повторная декомпиляция не выполнялась","saved project opened; sample and source SHA256 match; decompilation was not repeated"),
("python — содержимое архива; компилятор PE может относиться только к загрузчику","python is the archive content; the PE compiler may identify only the launcher"),
("анализ бинарных файлов извлечение ресурсов и декомпиляция в одном интерфейсе","binary analysis resource extraction and decompilation in one interface"),
("упакованный native-код может требовать отдельной распаковки перед ghidra","packed native code may require unpacking before ghidra"),
("оригинальный исходный код и полная эквивалентность не гарантируются","original source code and full equivalence are not guaranteed"),
("есть CLR data directory; исходный язык .net по нему не определяется","CLR data directory found; it does not identify the original .NET language"),
("ghidra не создала пользовательских функций; см. native-report.json","ghidra emitted no user functions; see native-report.json"),
("запуск окон, вкладки, конфигурация и поиск изображений проверены","windows tabs configuration and image matching tested"),
("часть native-функций не декомпилирована; см. native-report.json","some native functions could not be decompiled; see native-report.json"),
("исходники сохранены, но полная эквивалентность не подтверждена","sources saved but full equivalence is not confirmed"),
("не найдены .pyc; проверь extractor.log или включи все модули","no pyc files found; check extractor.log or include all modules"),
("формат не распознан; автоматическая декомпиляция недоступна","unrecognized format; automatic decompilation is unavailable"),
("корректность сверяй по equivalence results в pylingual.log","check equivalence results in pylingual.log for correctness"),
("неизвестный формат — автоматический выбор недоступен","unknown format — automatic routing is unavailable"),
("pyinstaller: CArchive cookie и границы архива","pyinstaller: CArchive cookie and archive bounds"),
("слишком много результатов с одинаковым именем","too many results with the same name"),
("qr-код появится после добавления адреса","a QR code will appear when the address is added"),
("проверь валюту и сеть перед переводом","verify the currency and network before sending"),
("не определён по встроенным сигнатурам","not identified by built-in signatures"),
("не удалось создать уникальный каталог","could not create a unique directory"),
("первый запуск может загружать модели","first use may download models"),
("декомпиляция python через pylingual","decompiling python with pylingual"),
("проверка полноты и эквивалентности","checking completeness and equivalence"),
("проверка функций и отчёта констант","checking functions and constants report"),
("расширенный анализ detect it easy","extended detect it easy analysis"),
("diec вернул не JSON; см. diec.log","diec returned non-JSON output; see diec.log"),
("слишком много извлечённых файлов","too many extracted files"),
("подготовка встроенных движков","preparing bundled engines"),
("извлечение архива pyinstaller","extracting pyinstaller archive"),
("открытие проверенного проекта","opening verified project"),
("обрезанный PE optional header","truncated PE optional header"),
("чтение заголовков и сигнатур","reading headers and signatures"),
("ручные исправления сохранены","manual corrections saved"),
("не удалось сохранить проект","failed to save project"),
("логи и частичные результаты","logs and partial results"),
("неверный ELF identification","invalid ELF identification"),
("обрезанная PE section table","truncated PE section table"),
("UPX: имя секции, эвристика","UPX: section-name heuristic"),
("формат модуля не поддержан","module format is unsupported"),
("секунд; процесс остановлен","seconds; process stopped"),
("файл вырос во время чтения","file grew while reading"),
("в настройках инструментов","in tool settings"),
("участков высокой энтропии","high-entropy regions"),
("загрузка движка и моделей","loading engines and models"),
("обрезанный Mach-O header","truncated Mach-O header"),
("инструмент завершился с","tool exited with"),
("поиск соседних модулей","discovering related modules"),
("поддержать разработку","support development"),
("исключено как runtime","filtered as runtime"),
("неверная PE-сигнатура","invalid PE signature"),
("обрезанный ELF header","truncated ELF header"),
("адрес скоро появится","address coming soon"),
("не найден инструмент","tool not found"),
("ilspy не создал .cs","ilspy emitted no C# files"),
("частичный результат","partial result"),
("сохранено ресурсов","resources saved"),
("управление потоком","control flow"),
("проверенный проект","verified project"),
("скопировать адрес","copy address"),
("объектов байткода","bytecode objects"),
("перевод объектов","object translation"),
("проект пропущен","project skipped"),
("автор: xreamm1","author: xreamm1"),
("укажи путь к","configure the path to"),
("не определён","not identified"),
("о программе","about"),
("файлов .pyc","pyc files"),
("файлов .py","python source files"),
("проверено","verified"),
("получено","emitted"),
("отменено","cancelled"),
("таймаут","timeout"),
("модулей","modules"),
("функций","functions"),
("запуск","launch"),
("модуль","module"),

    ("проверить обновления", "check for updates"),
    ("проверка обновлений", "checking for updates"),
    ("доступно обновление", "update available"),
    ("обновить", "update"),
    ("позже", "later"),
    ("больше не показывать", "do not show again"),
    ("загрузка обновления", "downloading update"),
    ("перезапустить и обновить", "restart and update"),
    ("обновлений нет", "no updates available"),
    (
        "очень длинные строки показаны до 8192 символов в просмотре",
        "very long lines show the first 8192 characters in viewing mode",
    ),
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
    ("загрузка модели", "model download"),
    ("ленивая декомпиляция native", "lazy native decompilation"),
    ("декомпиляция выбранной функции", "decompiling selected function"),
    ("функция декомпилирована", "function decompiled"),
    ("быстрый анализ native", "fast native analysis"),
    ("индекс функций готов", "native function index ready"),
    ("экспорт символов x64dbg", "export x64dbg symbols"),
    ("сравнить две базы", "compare two projects"),
    ("сравнение баз", "comparing projects"),
    ("исполняемая секция", "executable section"),
    ("байты отсутствуют в файле; восстановление кода требует распаковки", "file bytes are absent; code recovery requires unpacking"),
    ("строки и константы всех модулей", "strings and constants across modules"),
    ("показаны первые 1000 совпадений", "showing first 1000 matches"),
    ("прямые вызовы xrefs", "direct call xrefs"),
    ("кандидаты прямых вызовов — косвенные вызовы не разрешены", "direct call candidates; indirect calls are unresolved"),
    ("выбери ровно две базы для сравнения", "select exactly two projects to compare"),
    ("открой исходный бинарник для экспорта символов", "open the original binary to export symbols"),
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
    fn engine_log_and_reports_switch_to_english() {
        for text in ["чтение заголовков и сигнатур", "запуск: tool.exe\nлог: example.log", "исходники сохранены, но полная эквивалентность не подтверждена: [83.33]; см. python-report.json", "загрузка движка и моделей"]{
        let translated=translate(text,true);assert!(!translated.chars().any(|c|('а'..='я').contains(&c)),"{translated}");
      }
        assert_eq!(translate("about", false), "о программе");
    }
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
