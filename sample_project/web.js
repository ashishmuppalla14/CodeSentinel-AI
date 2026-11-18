// SYNTHETIC DEMO FILE - intentionally insecure
function render(userInput) {
  document.getElementById("out").innerHTML = userInput;
}

function runCode(code) {
  return eval(code);
}

function loadData() {
  try {
    return JSON.parse(localStorage.getItem("d"));
  } catch (e) {}
}

function findUser(db, name) {
  return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

function placeholder() {}
