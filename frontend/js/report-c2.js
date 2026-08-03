let currentType = 'file';
let selectedFile = null;

const toggle = document.getElementById('type-toggle');
const fileField = document.getElementById('file-field');
const valueField = document.getElementById('value-field');
const valueLabel = document.getElementById('value-label');
const valueInput = document.getElementById('value-input');
const dropzone = document.getElementById('dropzone');
const dropzoneLabel = document.getElementById('dropzone-label');
const fileInput = document.getElementById('file-input');
const form = document.getElementById('report-form');
const formError = document.getElementById('form-error');

const VALUE_LABELS = { url: 'Suspicious URL', ip: 'IP address', app: 'App name / package ID' };

toggle.addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  [...toggle.children].forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentType = btn.dataset.type;

  if (currentType === 'file') {
    fileField.style.display = 'block';
    valueField.style.display = 'none';
  } else {
    fileField.style.display = 'none';
    valueField.style.display = 'block';
    valueLabel.textContent = VALUE_LABELS[currentType];
    valueInput.placeholder = currentType === 'ip' ? '203.0.113.42' : currentType === 'app' ? 'com.example.fakebank' : 'https://example.com/suspicious-link';
  }
});

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) setFile(fileInput.files[0]);
});

function setFile(file) {
  selectedFile = file;
  dropzoneLabel.textContent = `Selected: ${file.name}`;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  formError.style.display = 'none';

  const description = document.getElementById('description').value.trim();
  const reporterName = document.getElementById('reporter-name').value.trim();
  const reporterContact = document.getElementById('reporter-contact').value.trim();

  if (description.length < 10) {
    showError('Please describe what happened in a bit more detail (at least 10 characters).');
    return;
  }
  if (currentType === 'file' && !selectedFile) {
    showError('Please select a file to upload.');
    return;
  }
  if (currentType !== 'file' && !valueInput.value.trim()) {
    showError(`Please enter the ${VALUE_LABELS[currentType].toLowerCase()}.`);
    return;
  }

  const submitBtn = form.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'Submitting…';

  try {
    let result;
    if (currentType === 'file') {
      const fd = new FormData();
      fd.append('file', selectedFile);
      fd.append('description', description);
      if (reporterName) fd.append('reporter_name', reporterName);
      if (reporterContact) fd.append('reporter_contact', reporterContact);
      result = await apiPostForm('/public/report/file', fd);
    } else {
      result = await apiPostJSON('/public/report/details', {
        report_type: currentType,
        description,
        submitted_value: valueInput.value.trim(),
        reporter_name: reporterName || null,
        reporter_contact: reporterContact || null,
      });
    }

    document.getElementById('form-card').style.display = 'none';
    document.getElementById('result-card').style.display = 'block';
    document.getElementById('ref-code').textContent = result.reference_code;
  } catch (err) {
    showError(err.message || 'Something went wrong. Please try again.');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Submit report';
  }
});

function showError(msg) {
  formError.textContent = msg;
  formError.style.display = 'block';
}
