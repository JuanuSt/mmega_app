/* Avoiding jQuery */
function onDOMReady(f){/in/.test(document.readyState)?setTimeout(arguments.callee.name+'('+f+')',9):f()}
function isNotBatman(a,h){for(;a&&a!==document;a=a.parentNode){if(a.classList.contains(h.substr(1))){return 1}}}
function fadeElement(a,b){if(b!=='show'){return a.style.opacity=setTimeout(function(){a.style.display='none'},200)*0}a.style.display='block';setTimeout(function(){a.style.opacity=1},30)}
function addListener(a,b,c){((typeof a=="string")?document.querySelector(a):a).addEventListener(b,c)}

/* Right menu code */
onDOMReady(function(){
    Array.from(document.querySelectorAll(".rmenu-host")).forEach((z,i)=>{
        addListener(z,"contextmenu",function(event){
            Array.from(document.querySelectorAll(".rmenu")).forEach((k,i)=>{k.style.display='none'});
            event.preventDefault();
            var mID='';
            Array.from(z.classList).forEach((y,i)=>{if(~y.indexOf("rmenu-id-")){mID='.'+y}});
            x=document.querySelector(".rmenu"+mID);
            var maxLeft=(window.innerWidth||document.documentElement.clientWidth||document.body.clientWidth)-10-x.getBoundingClientRect().width;
            var maxTop=(window.innerHeight||document.documentElement.clientHeight||document.body.clientHeight)-10-x.getBoundingClientRect().height;
            fadeElement(x,'show');
            x.style.left=(event.pageX>maxLeft?maxLeft:event.pageX)+"px",
            x.style.top=(event.pageY>maxTop?maxTop:event.pageY)+"px"
        })
    });
    Array.from(document.querySelectorAll(".rmenu li")).forEach((x,i)=>{
        addListener(x,"click",function(){
            if(eval("typeof(handleMenuAction)==typeof(Function)")&&!x.classList.contains("disabled")) handleMenuAction(x.getAttribute("data-action"), x.getAttribute("data-file") );
            fadeElement(x.parentElement,'hide')
        })
    });
    addListener(document,"mousedown",function(e){
        if(!isNotBatman(e.target,".rmenu-host")) Array.from(document.querySelectorAll(".rmenu")).forEach((x,i)=>{fadeElement(x,'hide')})
    })
});

/* Right menu actions */
function handleMenuAction(evt, file_id) {
    if (evt == 'delete')
        window.location.href=('/delete_remote_file/' + file_id);
    if (evt == 'move')
        window.location.href=('/move/' + file_id);
    if (evt == 'webdav')
        window.location.href=('/webdav/' + file_id);
    else
        alert("unknown action");
}
