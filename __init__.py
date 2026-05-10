from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    Sidebar,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
)
from PySide6.QtCore import Qt, QRectF
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTextEdit,
    QTabWidget,
    QWidget,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QSplitter,
    QFileDialog,
)
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor, QTextCharFormat, QBrush

from . import extractor, analyzer

def _make_label(text, bold=False, color=None):
    label = QLabel(text)
    label.setWordWrap(True)
    if bold:
        f = label.font()
        f.setBold(True)
        label.setFont(f)
    if color:
        label.setStyleSheet(f"color: {color};")
    return label

class InfoTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignTop)
        self.status = _make_label("Open a Node.js SEA binary to begin.", color="#888888")
        self.layout.addWidget(self.status)
        self.setLayout(self.layout)

    def clear(self):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def show_error(self, msg):
        self.clear()
        self.layout.addWidget(_make_label("Not a SEA binary", bold=True, color="#ff6b6b"))
        self.layout.addWidget(_make_label(msg, color="#888888"))

    def show_blob(self, blob):
        self.clear()
        self.layout.addWidget(_make_label("NODE_SEA_BLOB detected", bold=True, color="#51cf66"))
        self.layout.addWidget(QLabel(""))

        rows = [
            ("Magic",    blob.magic),
            ("Version",  str(blob.version)),
            ("Filename", blob.filename),
            ("Blob size", f"{blob.size:,} bytes"),
            ("JS size",  f"{len(blob.js_code):,} chars"),
        ]
        for key, val in rows:
            row = QHBoxLayout()
            k = QLabel(f"{key}:")
            k.setFixedWidth(80)
            f = k.font()
            f.setBold(True)
            k.setFont(f)
            row.addWidget(k)
            row.addWidget(QLabel(val))
            row.addStretch()
            self.layout.addLayout(row)

        self.layout.addStretch()

class JSTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        toolbar = QHBoxLayout()
        self.save_btn = QPushButton("Save JS to disk")
        self.save_btn.clicked.connect(self._save)
        toolbar.addStretch()
        toolbar.addWidget(self.save_btn)
        layout.addLayout(toolbar)

        self.editor = QTextEdit()
        self.editor.setReadOnly(True)
        self.editor.setFont(QFont("Menlo, Monaco, Courier New", 11))
        self.editor.setPlaceholderText("No JavaScript extracted yet.")
        layout.addWidget(self.editor)

        self.setLayout(layout)
        self._js_code = ""

    def set_code(self, js_code):
        self._js_code = js_code
        self.editor.setPlainText(js_code)

    def clear(self):
        self._js_code = ""
        self.editor.clear()

    def _save(self):
        if not self._js_code:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save extracted JS", "", "JavaScript (*.js);;All files (*)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._js_code)

class AnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.summary = _make_label("Run analysis to see results.", color="#888888")
        layout.addWidget(self.summary)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Category / Match", "Description"])
        self.tree.setColumnWidth(0, 260)
        self.tree.setAlternatingRowColors(True)
        layout.addWidget(self.tree)

        self.setLayout(layout)

    def clear(self):
        self.tree.clear()
        self.summary.setText("Run analysis to see results.")

    def show_results(self, results):
        self.tree.clear()

        if not results:
            self.summary.setText("No suspicious patterns detected.")
            return

        total = sum(len(v) for v in results.values())
        self.summary.setText(
            f"Found {total} indicator(s) across {len(results)} categories."
        )

        colors = {
            "Network":               "#74c0fc",
            "Process Execution":     "#ff6b6b",
            "Filesystem":            "#ffd43b",
            "Persistence":           "#f783ac",
            "Anti-Sandbox":          "#ff922b",
            "Crypto & Exfiltration": "#cc5de8",
            "Obfuscation Indicators":"#a9e34b",
        }

        for category, hits in results.items():
            color = colors.get(category, "#ffffff")
            parent = QTreeWidgetItem(self.tree, [f"[{category}]  ({len(hits)})", ""])
            parent.setForeground(0, QBrush(QColor(color)))
            f = parent.font(0)
            f.setBold(True)
            parent.setFont(0, f)

            seen = {}
            for match, desc in hits:
                if desc not in seen:
                    seen[desc] = []
                seen[desc].append(match)

            for desc, matches in seen.items():
                example = matches[0][:60] + ("…" if len(matches[0]) > 60 else "")
                child = QTreeWidgetItem(parent, [example, desc])
                child.setForeground(0, QBrush(QColor("#cccccc")))

            parent.setExpanded(True)

class SEAAnalyzerWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self._blob = None

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 8, 8, 8)

        header = QHBoxLayout()
        title = _make_label("SEA Analyzer", bold=True)
        title.setStyleSheet("font-size: 13px;")
        header.addWidget(title)
        header.addStretch()
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.setFixedHeight(24)
        self.analyze_btn.clicked.connect(self._run_analysis)
        self.analyze_btn.setEnabled(False)
        header.addWidget(self.analyze_btn)
        layout.addLayout(header)

        self.tabs = QTabWidget()
        self.info_tab = InfoTab()
        self.js_tab = JSTab()
        self.analysis_tab = AnalysisTab()

        self.tabs.addTab(self.info_tab, "Info")
        self.tabs.addTab(self.js_tab, "JavaScript")
        self.tabs.addTab(self.analysis_tab, "Analysis")
        layout.addWidget(self.tabs)

        self.setLayout(layout)

        if data:
            self._load(data)

    def _load(self, bv):
        self._blob = None
        self.js_tab.clear()
        self.analysis_tab.clear()
        self.analyze_btn.setEnabled(False)

        try:
            blob = extractor.extract(bv)
            self._blob = blob
            self.info_tab.show_blob(blob)
            self.js_tab.set_code(blob.js_code)
            self.analyze_btn.setEnabled(True)
        except extractor.SEAExtractionError as e:
            self.info_tab.show_error(str(e))

    def _run_analysis(self):
        if not self._blob:
            return
        results = analyzer.analyze(self._blob.js_code)
        self.analysis_tab.show_results(results)
        self.tabs.setCurrentIndex(2)

    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self.info_tab.show_error("No binary loaded.")
            self.js_tab.clear()
            self.analysis_tab.clear()
            self.analyze_btn.setEnabled(False)
        else:
            view = view_frame.getCurrentViewInterface()
            bv = view.getData()
            if bv:
                self._load(bv)

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

class SEAAnalyzerWidgetType(SidebarWidgetType):
    def __init__(self):
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 28))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "SEA")
        p.end()
        SidebarWidgetType.__init__(self, icon, "SEA Analyzer")

    def createWidget(self, frame, data):
        return SEAAnalyzerWidget("SEA Analyzer", frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext


Sidebar.addSidebarWidgetType(SEAAnalyzerWidgetType())
