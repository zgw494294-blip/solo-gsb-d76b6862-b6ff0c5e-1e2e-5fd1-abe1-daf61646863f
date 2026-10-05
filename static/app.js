// 离线网页样张审阅台 —— 主应用页面的少量原生 JS。
// 注意：此脚本只运行于主应用页面；沙盒预览页内没有任何脚本。
document.addEventListener('DOMContentLoaded', function () {
  // 文件选择后显示文件名与大小
  var input = document.querySelector('input[type="file"][name="file"]');
  var label = document.querySelector('[data-file-name]');
  if (input && label) {
    input.addEventListener('change', function () {
      if (!input.files.length) { label.textContent = ''; return; }
      var f = input.files[0];
      label.textContent = f.name + ' · ' + (f.size / 1024).toFixed(1) + ' KiB';
    });
  }
  // 删除等危险操作的确认
  Array.prototype.forEach.call(
    document.querySelectorAll('form[data-confirm]'),
    function (form) {
      form.addEventListener('submit', function (e) {
        if (!window.confirm(form.getAttribute('data-confirm'))) {
          e.preventDefault();
        }
      });
    }
  );
});
