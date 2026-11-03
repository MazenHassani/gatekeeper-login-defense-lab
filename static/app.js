const $ = id => document.getElementById(id);
$('run').addEventListener('click', async () => {
  const button = $('run');
  button.disabled = true;
  $('status').textContent = 'Running identical synthetic attempts through both pipelines…';
  try {
    const response = await fetch('/api/experiment', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({scenario:$('scenario').value,count:Number($('count').value),seed:Number($('seed').value)})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Experiment failed');
    const base = data.baseline.counts, gate = data.protected.counts;
    $('avoided').textContent = `${data.avoided} / ${data.count}`;
    $('percentage').textContent = `${data.avoided_percent}% fewer password verifications in this workload`;
    $('time').textContent = `${data.baseline.verification_ms.toFixed(0)} → ${data.protected.verification_ms.toFixed(0)}`;
    $('legit').textContent = `${gate.legitimate_accepted || 0} / ${gate.legitimate || 0}`;
    $('friction').textContent = `${gate.legitimate_challenged || 0} challenged · ${gate.legitimate_blocked || 0} blocked`;
    $('baseline').textContent = `${base.verifications} password checks · ${base.legitimate_accepted || 0} legitimate accepted`;
    $('decisions').textContent = `${gate.allow || 0} allowed · ${gate.challenge || 0} challenged · ${gate.reject || 0} rejected`;
    $('events').replaceChildren(...data.protected.events.map(event => {
      const row = document.createElement('tr');
      const values = [`${event.identity} / ${event.source}`,event.legitimate ? 'Legitimate' : 'Synthetic bot',event.risk,event.decision,event.verified ? 'Yes' : 'Avoided',event.accepted ? 'Accepted' : 'Generic failure'];
      values.forEach((value,index) => {const cell=document.createElement('td');const content=document.createElement(index===3?'span':'span');content.textContent=value;if(index===3)content.className=`badge ${event.decision}`;cell.append(content);row.append(cell);});
      return row;
    }));
    $('status').textContent = `Complete · seed ${data.seed} · ${data.iterations.toLocaleString()} PBKDF2 iterations · timings vary by machine and run`;
  } catch (error) { $('status').textContent = error.message; }
  finally { button.disabled = false; }
});
