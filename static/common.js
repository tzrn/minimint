function $(id) {
    return document.getElementById(id)
}

loc=window.location.hostname
addr = loc=="minimint.xyz" || loc=="www.minimint.xyz" ? "minimint.xyz/" : "127.0.0.1:3000/"

function req(p,b,m) {
    return fetch(`https://`+addr+p+"/", {
      method: m,
      body: JSON.stringify(b),
      headers: {
        "Content-type": "application/json"
      }
    });
}

function post(p, b) {
    return req(p, b, "POST")
}

function cookie(name) {
    return document.cookie.split(';').map(s=>s.split('=')).filter(c=>c[0].trim()==name)[0][1]
}

function delcookie(name, exp) {
    document.cookie=name+"=;expires=Thu, 01 Jan 1970 00:00:01 GMT"
}

function addcred(b) {
    try {
        b.ID=parseInt(cookie("ID"))
        b.Session=cookie("Session")
    } catch {
        b.ID=""
        b.Session=""
    }
    return b
}

function apost(p, b) {
    return post(p, addcred(b))
}

let lastNotif=0
function notify(msg) {
    $("notif").innerHTML+=`<p class="err" id="n${lastNotif}">${msg}</p>`
    setTimeout(()=>{
        $(`n${lastNotif}`).remove()
    }, 3000)
}
function info(msg) {
    $("notif").innerHTML+=`<p class="info" id="n${lastNotif}">${msg}</p>`
    setTimeout(()=>{
        $(`n${lastNotif}`).remove()
    }, 3000)
}

function esc(str) {
    return(str.replace('<','&lt;').replace('>','&gt;'))
}

function urls(str) {
    return str.replaceAll(/(https?:\/\/)?([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))/gi, "<a href='https://$2'>$1$2</a>");
}

function dateStr(date) {
        let d=new Date(date*1000)
        return `${d.toLocaleTimeString('ru-RU')} ${d.toLocaleDateString('ru-RU')}`
}

function formReply(j,showparent=true) {
        let d=new Date(j.Time*1000)
        let post=""
        post+=`<div><a href="/user.html?id=${j.UserID}">${j.Username}</a> <small>${d.toLocaleDateString('ru-RU')} ${d.toLocaleTimeString('ru-RU')}</small><p>${urls(esc(j.Contents))}</p>`
        post+=attachments2html(j.Attachments)
        let p = j.Parent
        if(p&&showparent) {
            let d=new Date(p.Time*1000)
            post+=`<b>in reply to <a href="/post.html?id=${j.Parent.ID}">post</a> by <a href="/user.html?id=${p.UserID}">${p.Username}</a>:</b><br> <div><small>${d.toLocaleDateString('ru-RU')} ${d.toLocaleTimeString('ru-RU')}</small><p>${urls(esc(p.Contents))}</p>`
            post+=attachments2html(j.Parent.Attachments)
        }
        post+=`<button onclick="initpost(${j.ID})">reply</button> <a href="/post.html?id=${j.ID}">${j.Replies} replies...</a></div><hr>`
    return post
}

function cancelpost() {
    $('post').style.display='none'
}

function newpost(parent,contents) {
    apost("post",{Contents:contents,ParentID:parent,Attachments:selectedFiles})
        .then(r=>r.json()).then(j=>{
            if(j.err) {
                notify(j.err)
            } else {
                window.location.assign(`/post.html?id=${j}`)
            }
        })
}


function initpost(parent) {
    $('post').style.display='flex'
    $('sendpost').onclick=()=>{
        newpost(parent, $('newpost').value)
    }
    $('newpost').value=''
    deselectFiles()
}

function attachments2html(attachments) {
    s=''
    for(const aid in attachments) {
        a=attachments[aid]
        switch(a.Type) {
            case 1:
            s+=`<img class="msgmedia" src="/files/${a.URL}"/>`
            break;
            case 2:
            s+=`<video controls class="msgmedia" src="/files/${a.URL}"></video>`
            break;
            case 3:
            s+=`<audio controls class="msgmedia" src="/files/${a.URL}"></audio>`
            break;
            default:
            s+=`<a href="/files/${a.URL}">file</a>`
            break;
        }
        s+='<br>'
    }
    return s
}

function tomsg(date, content, right, attachments) {
    s=`<div class="msg" ${right?'style="align-items:end;"':''}><small>${dateStr(date)}</small><p style="background-color:${right?"#FFDDDD":"beige"}">`
    s+=attachments2html(attachments)
    s+=`${urls(esc(content))}</p></div>`
    return s
}

var queue = []
const inaudio = new Audio("/in.wav");

function connect() {
    socket = new WebSocket(`wss://${addr}messagesock/`);

    socket.addEventListener('open', event => {
      socket.send(JSON.stringify(addcred({})));
    });

    socket.addEventListener('close', event => {
        //notify("connection lost, reconnecting in 2 seconds...")
        setTimeout(()=>{
            connect()
        }, 2000)
    });

    socket.addEventListener('error', event => {
        console.log("WebSocket error: ", event);
    });

    socket.addEventListener('message', event => {
        //console.log(event.data)
        //message sent, so add it to massages
        if(event.data=="k") {
            if(queue.length>0) {
                queue[0]()
                queue.slice(1)
            }
            return
        }
        d=JSON.parse(event.data)
        if(d.err) {
            notify(d.err)
            queue.slice(1)
        } else {
            inaudio.cloneNode().play()
            el=$("messages")
            if(el&&userid==d.From) {
                el.innerHTML+=tomsg(Date.now()/1000,d.Contents,false,d.Attachments)
                window.scrollTo(0, el.scrollHeight)
            } else {
                info(`<a href="/chat.html?id=${d.From}">${d.Username}: ${d.Contents}</a>`)
            }
        }
    });
}

if(window.location.pathname!="/login.html"&&window.location.pathname!="/register.html") {
    if(document.cookie=='') {
        window.location.replace(`/login.html`);
    }
    apost(`testauth`,{}).then(r=>{
        if(r.status==500) {
                window.location.replace(`/login.html`);
            } else {
                connect()
            }
    })
}

var files={}
var selectedFiles=[]

//default
function onFileSelect() {
    l=selectedFiles.length
    el=$('attachment_info')
    if(l==0) {
        el.innerHTML=''
    } else {
        el.innerHTML=`+${l} attachment(s)`
    }
}

function selectfile(chkbox, file) {
    if(chkbox.checked) {
        files[file].checkbox=chkbox
        selectedFiles.push(file)
    } else {
        selectedFiles=selectedFiles.filter(f=>f!=file)
    }
    onFileSelect()
}

function deselectFiles() {
    for(const f in selectedFiles) {
        n=selectedFiles[f]
        if(files[n]&&files[n].checkbox) {
           files[n].checkbox.checked=false 
        }
    }
    selectedFiles=[]
    if(onFileSelect) {
        onFileSelect()
    }
}

function loadfiles(page, query) {
    apost("files",{Page:page,Query:query}).then(r=>r.json()).then(j=>{
        if(j.err) {
            notify(j.err)
        } else {
            deselectFiles() /////TODO: remove this without breaking everything
            morebtn=$("morefiles")
            el=$('filelist')
            if(page==0) {
                el.innerHTML=''
            } else {
                morebtn=$('morefiles')
                if(morebtn) {
                    morebtn.remove()
                }
            }
            for(let i=0;i<j.Count;i++) {
                f=j.Fs[i]
                files[f.URL]=f
                str=''
                str+=`<div style="display:flex"><input onclick="selectfile(this, '${f.URL}')" type="checkbox"/>`
                switch(f.Type) {
                    case 1:
                    str+=`<div class="thumbwrap"><img class="thumb" src='/files/${f.URL}'/></div>`
                    break;
                    case 2:
                    str+=`<div class="thumbwrap"><img class="thumb" src='/video.png'/></div>`
                    break;
                    case 3:
                    str+=`<div class="thumbwrap"><img class="thumb" src='/audio.png'/></div>`
                    break;
                    default:
                    str+=`<div class="thumbwrap"><img class="thumb" src='/file.png'/></div>`
                    break;
                }
                str+=`<a class="filename" href="/files/${f.URL}">${f.Name}</a>`
                str+="</div><hr>"
                el.innerHTML+=str
            }
            if(j.Count==20) {
                el.innerHTML+=`<button id="morefiles" onclick="loadfiles(${page+1},'')">more</button>`
            }
        }
    })
}

function upload() {
    let files=$('file').files
    if(files.length==0) {
        notify("No files selected")
        return
    }
    let file=files[0]
    let form=new FormData();
    form.append("file",file);
    form.append("auth",JSON.stringify(addcred({})));

    info('uploading...')
    fetch(`https://${addr}upload/`,{
        method: "POST",
        body: form
    }).then(r=>{
        if(r.status==500) {
            r.json().then(j=>notify(j.err))
        } else {
            $('file').value=''
            info('done!')
            loadfiles(0,'')
        }
    })
}

function fileSearch() {
    loadfiles(0, $('filequery').value)
}
