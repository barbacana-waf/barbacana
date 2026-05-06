// Realistic JavaScript that exercises every shape the
// cross-site-scripting-function-call-evasion leaf catches when the
// same bytes appear in ARGS. Uploading this file as a multipart
// part must NOT trigger the rule — file-part bodies don't become
// ARGS in Coraza, so the new rules never see them.
function showAlert(msg) {
  alert.call(null, msg);
  confirm.apply(window, [msg]);
}
const myEval = eval.bind(window);
const grouped = (alert)(1);
const optional = alert?.(document?.cookie);
showAlert("hello");
