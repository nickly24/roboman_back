DELETE FROM settings WHERE `key` IN ('telegram_bot_token', 'telegram_bot_token_dev');

DROP TABLE IF EXISTS crm_chat_read_state;
DROP TABLE IF EXISTS crm_chat_comments;
DROP TABLE IF EXISTS crm_registration_requests;
DROP TABLE IF EXISTS crm_messages;
DROP TABLE IF EXISTS crm_notification_subscribers;
DROP TABLE IF EXISTS crm_chats;

UPDATE settings
SET description = 'AITUNNEL API ключ для ИИ-поиска детских садов'
WHERE `key` = 'aitunnel_api_key';
