// Without JavaScript all workloads remain readable, including their tables.
const workload = document.getElementById('benchmark-workload');
if (workload) {
  const panels = [...document.querySelectorAll('[data-benchmark-panel]')];
  const show = () => {
    for (const panel of panels) panel.hidden = panel.dataset.benchmarkPanel !== workload.value;
  };
  workload.addEventListener('change', show);
  show();
}
