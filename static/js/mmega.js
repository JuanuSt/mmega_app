
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

function unset_all(id) {
    window.location.href=('/webdav/unset_all/' + id)
}

function unset(file_id) {
    window.location.href=('/webdav/unset/' + file_id)
}

function copy_link(link_id) {
    var copyValue = document.getElementById('link_' + link_id);
    copyValue.style.display = 'block';
    copyValue.focus();
    copyValue.select();
    document.execCommand('SelectAll');
    document.execCommand('copy', false, null);
    copyValue.style.display = 'none';
    alert("link copied to clipboard: " + copyValue.value);
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
