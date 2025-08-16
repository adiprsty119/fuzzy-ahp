// function sidebarState() {
//   return {
//     isCollapsed: initialSidebarState === "collapsed",
//     toggleSidebar() {
//       this.isCollapsed = !this.isCollapsed;
//       saveSidebarState(this.isCollapsed ? "collapsed" : "expanded");
//     },
//   };
// }

// function saveSidebarState(state) {
//   fetch("/save_sidebar_state", {
//     method: "POST",
//     headers: {
//       "Content-Type": "application/json",
//     },
//     body: JSON.stringify({ state: state }),
//   })
//     .then((response) => response.json())
//     .then((data) => {
//       console.log("State saved:", data);
//     })
//     .catch((err) => console.error("Error saving state:", err));
// }
