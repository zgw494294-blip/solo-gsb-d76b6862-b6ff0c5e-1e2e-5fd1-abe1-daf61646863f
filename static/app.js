// 主应用界面的少量增强（与预览隔离无关，预览页不加载任何脚本）。
document.addEventListener("DOMContentLoaded", () => {
  // 文件选择后显示文件名
  const input = document.getElementById("file-input");
  const label = document.getElementById("file-label");
  if (input && label) {
    input.addEventListener("change", () => {
      label.textContent = input.files.length ? input.files[0].name : "选择 ZIP 文件…";
    });
  }

  // 删除确认
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });
});
