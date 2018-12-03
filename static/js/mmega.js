
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


/* 
document.querySelectorAll('input[type=number]')
.forEach(e => e.oninput = () => {
  // Always 2 digits
  if (e.value.length >= 2) e.value = e.value.slice(0, 2);
  // 0 on the left (doesn't work on FF)
  if (e.value.length === 1) e.value = '0' + e.value;
  // Avoiding letters on FF
  if (!e.value) e.value = '00';
});

function todaydate(){
    var today_date= new Date()
    var myyear=today_date.getYear()
    var mymonth=today_date.getMonth()+1
    var mytoday=today_date.getDate()
    document.write(myyear+"/"+mymonth+"/"+mytoday)
}
 */