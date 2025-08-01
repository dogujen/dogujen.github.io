fetch(`https://api.github.com/users/${username}/repos?sort=updated`)
    .then(res => res.json())
    .then(repos => {
      const container = document.getElementById("project-list");
      container.innerHTML = "";

      repos.forEach(repo => {
        const updatedDate = new Date(repo.updated_at).toLocaleDateString('tr-TR', {
          year: 'numeric', month: 'short', day: 'numeric'
        });

        const article = document.createElement("article");
        article.className = "card-wrapper card mb-4";

        article.innerHTML = `
          <a href="${repo.html_url}" class="post-preview row g-0 flex-md-row-reverse text-decoration-none">
            <div class="col-md-12">
              <div class="card-body d-flex flex-column h-100">
                <h1 class="card-title h4 my-2 mt-md-0">${repo.name}</h1>
                <div class="card-text content mt-0 mb-3">
                  <p>${repo.description || "No desc."}</p>
                </div>
                <div class="post-meta mt-auto d-flex align-items-end">
                  <div class="me-auto">
                    <i class="far fa-calendar fa-fw me-1"></i>
                    <time>${updatedDate}</time>
                    <span class="ms-3">
                      <i class="far fa-star fa-fw me-1"></i> ${repo.stargazers_count}
                    </span>
                    <span class="ms-3">
                      <i class="fas fa-code-branch fa-fw me-1"></i> ${repo.forks_count}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </a>
        `;

        container.appendChild(article);
      });
    })
    .catch(err => {
      console.error("GitHub API err:", err);
      document.getElementById("project-list").innerHTML = `
        <article class="card-wrapper card">
          <div class="card-body">
            <p>err.</p>
          </div>
        </article>`;
    });