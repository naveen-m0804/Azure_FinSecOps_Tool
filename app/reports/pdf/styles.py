from reportlab.lib.colors import HexColor
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

# CGI-inspired corporate palette
COLOR_PRIMARY_RED = HexColor("#DE1A3B")
COLOR_PRIMARY_PURPLE = HexColor("#5735A7")
COLOR_DARK = HexColor("#1A202C")
COLOR_MUTED = HexColor("#718096")
COLOR_LIGHT_BG = HexColor("#F7FAFC")
COLOR_BORDER = HexColor("#E2E8F0")
COLOR_WHITE = HexColor("#FFFFFF")
COLOR_SEV_CRITICAL = HexColor("#9B2C2C")
COLOR_SEV_HIGH = HexColor("#DE1A3B")
COLOR_SEV_MEDIUM = HexColor("#DD6B20")
COLOR_SEV_LOW = HexColor("#3182CE")
COLOR_SEV_INFO = HexColor("#718096")

class NumberedCanvas(canvas.Canvas):
    """Adds running headers and page numbers to multi-page ReportLab documents."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        if self._pageNumber == 1:
            return # Skip cover page

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(COLOR_MUTED)

        w, h = self._pagesize
        margin = 20 if w > 700 else 54

        # Header
        header_y = h - 16
        self.drawString(margin, header_y, "Azure FinSecOps - Security Assessment Report")
        self.setStrokeColor(COLOR_BORDER)
        self.setLineWidth(0.5)
        self.line(margin, header_y - 3, w - margin, header_y - 3)

        # Footer
        footer_y = 12
        self.line(margin, footer_y + 9, w - margin, footer_y + 9)
        self.drawString(margin, footer_y, "Confidential - Enterprise Deliverable")
        self.drawRightString(w - margin, footer_y, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()

def get_report_stylesheet():
    base = getSampleStyleSheet()

    styles = {
        "CoverTitle": ParagraphStyle(
            "CoverTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=26,
            leading=32,
            textColor=COLOR_PRIMARY_PURPLE,
            alignment=0,
            spaceAfter=12
        ),
        "CoverSubtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=13,
            leading=18,
            textColor=COLOR_DARK,
            spaceAfter=24
        ),
        "CoverMeta": ParagraphStyle(
            "CoverMeta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=14,
            textColor=COLOR_MUTED
        ),
        "SectionHeader": ParagraphStyle(
            "SectionHeader",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=COLOR_PRIMARY_PURPLE,
            spaceBefore=16,
            spaceAfter=8,
            keepWithNext=True
        ),
        "SubSectionHeader": ParagraphStyle(
            "SubSectionHeader",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=COLOR_DARK,
            spaceBefore=10,
            spaceAfter=6,
            keepWithNext=True
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=COLOR_DARK,
            spaceAfter=6
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=COLOR_WHITE
        ),
        "TableCell": ParagraphStyle(
            "TableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=COLOR_DARK
        ),
        "TableCellBold": ParagraphStyle(
            "TableCellBold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9.5,
            textColor=COLOR_DARK
        ),
        "TableHeaderSmall": ParagraphStyle(
            "TableHeaderSmall",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=8.5,
            textColor=COLOR_WHITE
        ),
        "TableCellSmall": ParagraphStyle(
            "TableCellSmall",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=6.5,
            leading=8,
            textColor=COLOR_DARK
        ),
        "TableCellSmallBold": ParagraphStyle(
            "TableCellSmallBold",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=6.5,
            leading=8,
            textColor=COLOR_DARK
        ),
        "BadgeCritical": ParagraphStyle(
            "BadgeCritical",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=8,
            textColor=COLOR_SEV_CRITICAL
        ),
        "BadgeHigh": ParagraphStyle(
            "BadgeHigh",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=8,
            textColor=COLOR_SEV_HIGH
        ),
    }
    return styles
