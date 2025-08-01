 fetch(`https://api.github.com/users/dogujen/repos?sort=created`)
    .then(res => res.json())
    .then(repos => {
      const container = document.getElementById("repo-container");
      container.innerHTML = ""; 

      repos.forEach(repo => {
        const card = document.createElement("article");
        card.className = "card-wrapper card";

        card.innerHTML = `
          <a href="${repo.html_url}" class="post-preview row g-0 flex-md-row-reverse text-decoration-none text-dark">
            <div class="col-md-12">
              <div class="card-body d-flex flex-column">
                <h1 class="card-title h4 my-2 mt-md-0">${repo.name}</h1>
                <div class="card-text content mt-0 mb-3">
                  <p>${repo.description ? repo.description : "No Description."}</p>
                </div>
                <div class="post-meta flex-grow-1 d-flex align-items-end">
                  <div class="me-auto">
                    <i class="far fa-star me-1"></i> ⭐ ${repo.stargazers_count}
                    <i class="far fa-code-branch ms-3 me-1"></i> 🍴 ${repo.forks_count}
                    <i class="far fa-calendar ms-3 me-1"></i>
                    <time>${new Date(repo.updated_at).toLocaleDateString()}</time>
                  </div>
                </div>
              </div>
            </div>
          </a>
        `;
        container.appendChild(card);
      });
    })
    .catch(err => {
      console.error(err);
      document.getElementById("repo-container").innerHTML = '<div class="card p-3">Projects couldn\'t load.</div>';
    });