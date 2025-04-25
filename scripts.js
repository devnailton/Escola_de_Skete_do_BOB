document.addEventListener('DOMContentLoaded', () => {

  // Função para inscrição nas aulas
  window.inscrever = function(aula) {
    alert(`Obrigado por se inscrever na aula: ${aula}`);
  };

  // Formulário voluntariado
  const volunteerForm = document.getElementById('volunteer-form');
  if (volunteerForm) {
    volunteerForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const nomeInput = volunteerForm.querySelector('#nome');
      const emailInput = volunteerForm.querySelector('#email');

      if (nomeInput && emailInput) {
        const nome = nomeInput.value.trim();
        const email = emailInput.value.trim();

        if (nome && email) {
          alert(`Obrigado, ${nome}! Sua mensagem foi recebida. Entraremos em contato pelo email: ${email} em breve.`);
          volunteerForm.reset();
        } else {
          alert('Por favor, preencha todos os campos obrigatórios.');
        }
      } else {
        alert('Ocorreu um erro ao processar o formulário. Tente novamente.');
      }
    });
  }
});