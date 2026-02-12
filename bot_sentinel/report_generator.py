from fpdf import FPDF
from datetime import datetime
import os

class SentinelReport(FPDF):
    def header(self):
        # Logo ou Título
        self.set_font('Arial', 'B', 16)
        self.set_text_color(112, 0, 255) # Cor roxa do projeto
        self.cell(0, 10, 'SENTINEL OSINT - RELATORIO DE VIGILANCIA', 0, 1, 'C')
        self.set_font('Arial', '', 10)
        self.set_text_color(100)
        self.cell(0, 5, f'Gerado em: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(150)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(profile_data, findings, filename="relatorio_sentinel.pdf"):
    """
    profile_data: tuple (id, name, cpf, phone, rg, created_at)
    findings: list of tuples (source, content, link, found_at)
    """
    pdf = SentinelReport()
    pdf.add_page()
    
    # Seção: Dados do Perfil
    pdf.set_font('Arial', 'B', 12)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, ' 👤 DADOS DO PERFIL MONITORADO', 0, 1, 'L', fill=True)
    pdf.ln(2)
    
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 7, f'Nome Completo: {profile_data[1]}', 0, 1)
    pdf.cell(0, 7, f'CPF: {profile_data[2]}', 0, 1)
    pdf.cell(0, 7, f'Telefone: {profile_data[3]}', 0, 1)
    pdf.cell(0, 7, f'RG: {profile_data[4] if profile_data[4] else "Nao informado"}', 0, 1)
    pdf.ln(10)
    
    # Seção: Descobertas
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, ' 🚨 DESCOBERTAS E EXPOSICOES DETECTADAS', 0, 1, 'L', fill=True)
    pdf.ln(5)
    
    if not findings:
        pdf.set_font('Arial', 'I', 10)
        pdf.cell(0, 10, 'Nenhuma exposicao encontrada neste periodo.', 0, 1)
    else:
        for f in findings:
            source, content, link, found_at = f
            
            # Caixa de achado
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(200, 0, 0) # Vermelho para alerta
            pdf.cell(0, 7, f'FONTE: {source}', 0, 1)
            pdf.set_text_color(0)
            
            pdf.set_font('Arial', '', 9)
            pdf.multi_cell(0, 5, f'Descricao: {content}')
            pdf.set_text_color(0, 0, 255) # Azul para link
            pdf.write(5, f'Link: {link}', link)
            pdf.ln(5)
            pdf.set_text_color(100)
            pdf.cell(0, 5, f'Detectado em: {found_at}', 0, 1)
            pdf.ln(5)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)
            pdf.set_text_color(0)

    # Recomendações
    pdf.add_page()
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, ' 🛡️ RECOMENDACOES DE SEGURANCA', 0, 1, 'L', fill=True)
    pdf.ln(5)
    rec_text = [
        "1. Troque suas senhas nos servicos listados acima.",
        "2. Ative a Autenticacao de Dois Fatores (2FA) em todas as contas.",
        "3. Solicite a remocao de seus dados junto aos sites de Data Brokers.",
        "4. Fique atento a tentativas de phishing via telefone ou e-mail.",
        "5. Revise as configuracoes de privacidade de suas redes sociais."
    ]
    pdf.set_font('Arial', '', 10)
    for line in rec_text:
        pdf.cell(0, 7, line, 0, 1)

    # Salva o arquivo temporariamente
    output_path = os.path.join(os.path.dirname(__file__), filename)
    pdf.output(output_path)
    return output_path

if __name__ == "__main__":
    # Teste rápido
    mock_profile = (1, "Joao da Silva", "123.456.789-00", "11999999999", "12.345.678-9", "2026-02-12")
    mock_findings = [
        ("Google Dorks", "Mention found on Pastebin leak list", "https://pastebin.com/raw/xyz", "2026-02-12 10:00"),
        ("Sherlock", "New profile detected on Instagram", "https://instagram.com/joaosilva", "2026-02-12 11:00")
    ]
    generate_pdf_report(mock_profile, mock_findings)
    print("Relatorio de teste gerado.")
