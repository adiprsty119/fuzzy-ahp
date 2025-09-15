document.addEventListener("alpine:init", () => {
  Alpine.data("sidebarState", () => ({
    isOpen: true, // default sidebar terbuka
    toggle() {
      this.isOpen = !this.isOpen;
    },
    close() {
      this.isOpen = false;
    },
    open() {
      this.isOpen = true;
    },
  }));
});
