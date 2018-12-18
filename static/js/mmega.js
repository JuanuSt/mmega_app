
function toggle_visibility(id) {
    var x = document.getElementById(id);
    if (x.style.display === "none") {
        x.style.display = "flex";
    } else {
        x.style.display = "none";
    }
}

function show_config(id) {
	window.location.href=('/config/' + id)
}

function show_files(id) {
	window.location.href=('/files/' + id)
}

function files_details(id) {
	window.location.href=('/files_details/' + id)
}

function update_full(id) {
	window.location.href=('/update/' + id)
}

function upload(id) {
	window.location.href=('/upload/' + id)
}

function sync(id) {
	window.location.href=('/sync/' + id)
}
