  fetch(`https://api.github.com/users/dogujen/repos?sort=updated`)
    .then(res => res.json())
    .then(repos => {
      const container = document.getElementById("project-list");
      container.innerHTML = "";

      repos.forEach(repo => {
        const card = document.createElement("article");
        card.className = "card-wrapper card";

        const updatedDate = new Date(repo.updated_at).toLocaleDateString('tr-TR', {
          year: 'numeric', month: 'short', day: 'numeric'
        });

        card.innerHTML = `
          <a href="${repo.html_url}" class="post-preview row g-0 flex-md-row-reverse text-decoration-none">
            <div class="col-md-12">
              <div class="card-body d-flex flex-column">
                <h1 class="card-title h4 my-2 mt-md-0">${repo.name}</h1>
                <div class="card-text content mt-0 mb-3">
                  <p>${repo.description ? repo.description : "No Description."}</p>
                </div>
                <div class="post-meta flex-grow-1 d-flex align-items-end">
                  <div class="me-auto">
                    <i class="far fa-calendar fa-fw me-1"></i>
                    <time>${updatedDate}</time>
                    <i class="far fa-star fa-fw ms-3 me-1"></i>
                    ${repo.stargazers_count}
                    <i class="fas fa-code-branch fa-fw ms-3 me-1"></i>
                    ${repo.forks_count}
                  </div>
                </div>
              </div>
            </div>
          </a>
        `;

        container.appendChild(card);
      });
    })
    .catch(error => {
      console.error("GitHub API Err:", error);
      const container = document.getElementById("project-list");
      container.innerHTML = `
        <article class="card-wrapper card">
          <div class="card-body">
            <p>Err</p>
          </div>
        </article>`;
    });