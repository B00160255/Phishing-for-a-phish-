document.getElementById('scanBtn').onclick = async () => {
  let res = await fetch('http://127.0.0.1:5000/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sender_domain: document.getElementById('senderDomain').value, email_text: document.getElementById('emailText').value })
  });
  let data = await res.json();
  document.getElementById('result').innerText = `Verdict: ${data.colour} | Score: ${data.score}\nReason: ${data.reason}`;
};