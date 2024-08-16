function showNavigationLoader() {
	var navigationLoader = document.querySelector("#navigate-away-loader")
	navigationLoader.style.visibility = "visible"
	navigationLoader.style.opacity = 1
	navigationLoader.style.pointerEvents = "all"

	document.querySelector("#navigate-away-loader > svg").style.animation =
		"spin 1.5s infinite linear"
}

function hideNavigationLoader() {
	var navigationLoader = document.querySelector("#navigate-away-loader")
	navigationLoader.style.visibility = "hidden"
	navigationLoader.style.opacity = 0
	navigationLoader.style.pointerEvents = "none"
}

window.addEventListener("beforeunload", function (e) {
	showNavigationLoader()
	return true
})
window.addEventListener("pageshow", function (e) {
	hideNavigationLoader()
})
