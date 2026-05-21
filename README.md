# mtproto

**Учебный проект** — создан в ознакомительных целях для изучения протокола MTProto и генерации ключа авторизации (auth key) на языке Rust.

## Описание

Этот репозиторий содержит реализацию механизма создания ключа авторизации (auth key) для протокола **MTProto** (используется в Telegram) на языке **Rust**.

Проект разработан исключительно в **учебных целях** для понимания:
- принципов работы протокола MTProto;
- процесса Diffie-Hellman key exchange;
- генерации и валидации auth key;
- практики написания сетевого кода на Rust.

## Требования

- [Rust](https://www.rust-lang.org/) (последняя стабильная версия)
- [Cargo](https://doc.rust-lang.org/cargo/)

## Сборка и запуск

```bash
# Клонирование репозитория
git clone https://github.com/megawattka/mtproto.git
cd mtproto

# Сборка проекта
cargo build --release

# Запуск
cargo run
```

## Зависимости

Основные зависимости проекта указаны в `Cargo.toml`. Для работы с криптографией MTProto обычно используются:
- криптографические примитивы (например, `aes`, `sha1`, `rsa`);
- библиотеки для работы с большими числами (`num-bigint`);
- сетевые библиотеки (`tokio`, `async-trait` и др.) — при наличии сетевого взаимодействия.

> Подробный список см. в файле [`Cargo.toml`](./Cargo.toml).

## Что изучено / реализовано

- [x] Генерация auth key по протоколу MTProto
- [ ] Полноценный клиент MTProto
- [ ] Шифрование и расшифровка сообщений
- [ ] Обработка сессий и seqno

## Полезные ссылки

- [MTProto Protocol Specification](https://core.telegram.org/mtproto)
- [Telegram API Documentation](https://core.telegram.org/api)
- [Rust Book (RU)](https://doc.rust-lang.ru/book/)

## Автор

- GitHub: [@megawattka](https://github.com/megawattka)

## Лицензия

Этот проект распространяется под лицензией MIT. Подробности см. в файле `LICENSE` (если присутствует) или уточняйте у автора.

---

*Создано с целью изучения и не является официальной реализацией протокола MTProto.*
