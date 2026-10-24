# Disabling php-php2shell-session-upload-progress does not touch the
# php-injection bucket next to it:
# an inline PHP open tag (php-injection-open-tags) is still blocked.
GET {{host}}/?code=%3C%3Fphp%20echo%201%3B%20%3F%3E
HTTP 403
[Asserts]
jsonpath "$.error" == "blocked"
