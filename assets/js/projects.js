fetch(`https://api.github.com/users/dogujen/repos?sort=created`)
  .then(res => res.json())
  .then(repos => {
    const container = document.getElementById("archives");
    const grouped = {};

    repos.forEach(repo => {
      const updated = new Date(repo.updated_at);
      const year = updated.getFullYear();
      if (!grouped[year]) grouped[year] = [];
      grouped[year].push({ repo, updated });
    });

    const years = Object.keys(grouped).sort((a, b) => b - a);

    years.forEach(year => {
      const yearSection = document.createElement("div");

      yearSection.innerHTML = `
        <time class="year lead d-block">${year}</time>
        <ul class="list-unstyled"></ul>
      `;

      const ul = yearSection.querySelector("ul");

      grouped[year]
        .sort((a, b) => new Date(b.updated) - new Date(a.updated))
        .forEach(({ repo, updated }) => {
          const li = document.createElement("li");

          const day = updated.toLocaleDateString('tr-TR', { day: '2-digit' });
          const month = updated.toLocaleDateString('tr-TR', { month: 'short' });

          li.innerHTML = `
            <span class="date day" data-ts="${+updated}" data-df="DD">${day}</span>
            <span class="date month small text-muted ms-1" data-ts="${+updated}" data-df="/ MM">${month}</span>
            <a href="${repo.html_url}">${repo.name}</a>
          `;

          ul.appendChild(li);
        });

      container.appendChild(yearSection);
    });
  })
  .catch(err => {
    console.error("GitHub API err:", err);
    document.getElementById("archives").innerHTML = `
      <article class="card-wrapper card">
        <div class="card-body">
          <p>Err.</p>
        </div>
      </article>`;
  });