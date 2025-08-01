  fetch(`https://api.github.com/users/dogujen/repos?sort=updated`)
    .then(response => {
      if (!response.ok) throw new Error("API yanıtı başarısız");
      return response.json();
    })
    .then(repos => {
      const list = document.getElementById("repo-list");
      list.innerHTML = "";

      if (repos.length === 0) {
        list.innerHTML = "<li>Couldn't find anything.</li>";
        return;
      }

      repos.forEach(repo => {
        const item = document.createElement("li");
        item.innerHTML = `
          <strong><a href="${repo.html_url}" target="_blank">${repo.name}</a></strong><br>
          <small>${repo.description ? repo.description : "No description."}</small>
        `;
        list.appendChild(item);
      });
    })
    .catch(error => {
      console.error("Hata:", error);
      document.getElementById("repo-list").innerHTML = "<li>Error</li>";
    });