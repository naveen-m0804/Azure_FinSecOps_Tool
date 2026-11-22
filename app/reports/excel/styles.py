from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

FONT_HEADER = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
FONT_TITLE = Font(name="Segoe UI", size=14, bold=True, color="5735A7")
FONT_BOLD = Font(name="Segoe UI", size=10, bold=True)
FONT_BODY = Font(name="Segoe UI", size=10)
FONT_MUTED = Font(name="Segoe UI", size=9, color="718096")
FONT_SUCCESS = Font(name="Segoe UI", size=10, color="059669")
FONT_SUCCESS_BOLD = Font(name="Segoe UI", size=10, bold=True, color="047857")
FONT_DANGER = Font(name="Segoe UI", size=10, color="DE1A3B")

FILL_PURPLE_HEADER = PatternFill(start_color="5735A7", end_color="5735A7", fill_type="solid")
FILL_RED_HEADER = PatternFill(start_color="DE1A3B", end_color="DE1A3B", fill_type="solid")
FILL_ZEBRA = PatternFill(start_color="F7FAFC", end_color="F7FAFC", fill_type="solid")
FILL_HIGHLIGHT = PatternFill(start_color="EDF2F7", end_color="EDF2F7", fill_type="solid")

ALIGN_LEFT = Alignment(horizontal="left", vertical="center")
ALIGN_CENTER = Alignment(horizontal="center", vertical="center")
ALIGN_RIGHT = Alignment(horizontal="right", vertical="center")
ALIGN_WRAP = Alignment(horizontal="left", vertical="center", wrap_text=True)

THIN_BORDER_SIDE = Side(border_style="thin", color="E2E8F0")
BORDER_BOX = Border(left=THIN_BORDER_SIDE, right=THIN_BORDER_SIDE, top=THIN_BORDER_SIDE, bottom=THIN_BORDER_SIDE)
