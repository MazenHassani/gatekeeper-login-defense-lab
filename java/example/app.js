const ids=['evaluated','admitted','denied','successes','failures','inFlight','busy','storeErrors'];
async function refresh(){try{const response=await fetch('/api/metrics');if(!response.ok)return;const data=await response.json();for(const id of ids)document.getElementById(id).textContent=data[id];}catch{document.getElementById('status').textContent='Local server unavailable.';}}
async function send(valid,count){
 const buttons=[...document.querySelectorAll('button')];buttons.forEach(button=>button.disabled=true);
 const totals={accepted:0,invalid:0,denied:0};
 try{for(let i=0;i<count;i++){
  const response=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({username:'demo',password:valid?'local-example-only':'incorrect-example-password'})});
  if(response.status===200)totals.accepted++;else if(response.status===401)totals.invalid++;else totals.denied++;
 }
 document.getElementById('status').textContent=`${totals.accepted} authenticated · ${totals.invalid} invalid · ${totals.denied} denied before password work. Limits expire after 60 seconds.`;
 }catch{document.getElementById('status').textContent='Local request failed.';}
 finally{buttons.forEach(button=>button.disabled=false);await refresh();}
}
document.getElementById('correct').addEventListener('click',()=>send(true,1));
document.getElementById('wrong').addEventListener('click',()=>send(false,1));
document.getElementById('batch').addEventListener('click',()=>send(false,8));
refresh();setInterval(refresh,1500);
