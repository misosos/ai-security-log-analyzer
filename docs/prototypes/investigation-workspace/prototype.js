(() => {
  const tabs = [...document.querySelectorAll('[role="tab"]')];

  function selectTab(tab, moveFocus = false) {
    tabs.forEach((item) => {
      const selected = item === tab;
      item.setAttribute('aria-selected', String(selected));
      item.tabIndex = selected ? 0 : -1;
      document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
    });
    if (moveFocus) tab.focus();
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => selectTab(tab));
    tab.addEventListener('keydown', (event) => {
      let next = null;
      if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
      if (event.key === 'ArrowLeft') next = tabs[(index - 1 + tabs.length) % tabs.length];
      if (event.key === 'Home') next = tabs[0];
      if (event.key === 'End') next = tabs.at(-1);
      if (next) {
        event.preventDefault();
        selectTab(next, true);
      }
    });
  });

  document.querySelectorAll('[data-select-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      const target = tabs.find((tab) => tab.id === `tab-${button.dataset.selectTab}`);
      if (target) {
        selectTab(target);
        target.focus();
      }
    });
  });

  const tasks = [
    {
      title: '자료 범위와 시간 경계 확인',
      description: '수집된 자료가 해당 시간 범위를 충분히 포함하는지, 누락이나 지연 가능성이 있는지 확인하세요.',
      how: '승인된 내부 분석 절차에서 자료 범위와 수집 상태를 비교합니다. 이 prototype은 명령을 실행하지 않습니다.',
      citation: '자료 범위를 확인하는 일반 조사 참고사항입니다. 이 검토 건의 사실이나 공격 증거가 아닙니다.',
    },
    {
      title: '실패와 성공 기록 비교',
      description: '두 결과의 시간 순서와 관찰된 범위가 일치하는지 확인하세요. 관계만으로 원인을 단정하지 않습니다.',
      how: '승인된 내부 분석 절차에서 결과 유형과 관찰 시각을 각각 대조합니다.',
      citation: '서로 다른 인증 결과를 구분하는 일반 조사 참고사항입니다. 사례의 직접 증거가 아닙니다.',
    },
    {
      title: '성공 이후의 세션 활동 확인',
      description: '성공 기록 뒤의 자료가 제공되는지 확인하고, 확인할 수 없는 범위를 기록합니다.',
      how: '승인된 내부 경로에서 해당 범위의 후속 자료 유무와 coverage를 확인합니다.',
      citation: '후속 활동을 검토할 때의 일반적인 조사 범위 안내입니다. 이 사례의 침해 여부를 판정하지 않습니다.',
    },
  ];

  const choices = [...document.querySelectorAll('[data-task]')];
  choices.forEach((choice) => {
    choice.addEventListener('click', () => {
      choices.forEach((item) => {
        const selected = item === choice;
        item.classList.toggle('is-selected', selected);
        item.setAttribute('aria-pressed', String(selected));
      });
      const task = tasks[Number(choice.dataset.task)];
      const index = Number(choice.dataset.task) + 1;
      document.getElementById('task-detail-kicker').textContent = `작업 ${index}`;
      document.getElementById('task-detail-title').textContent = task.title;
      document.getElementById('task-detail-description').textContent = task.description;
      document.getElementById('task-how').textContent = task.how;
      document.getElementById('task-citation').textContent = task.citation;
    });
  });
})();
