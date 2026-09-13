#include "views.h"
#include "theme.h"

#include <QAction>
#include <QFile>
#include <QFileDialog>
#include <QGraphicsItem>
#include <QGraphicsScene>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSplitter>
#include <QTextBlock>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <cstdio>

namespace {

QVBoxLayout* fill(QWidget* owner, QWidget* child)
{
    auto* layout = new QVBoxLayout(owner);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    layout->addWidget(child);
    owner->setFocusProxy(child);
    return layout;
}

QString hex(std::uint64_t value)
{
    return QStringLiteral("%1").arg(value, 0, 16).toUpper();
}

} // namespace

TableView::TableView(const QStringList& headers, QWidget* parent)
    : QTableWidget(0, int(headers.size()), parent)
{
    setHorizontalHeaderLabels(headers);
    setFont(theme::monospaceFont());
    setEditTriggers(NoEditTriggers);
    setSelectionBehavior(SelectRows);
    setSelectionMode(SingleSelection);
    setShowGrid(false);
    setWordWrap(false);
    verticalHeader()->hide();
    verticalHeader()->setDefaultSectionSize(fontMetrics().height() + 4);
    horizontalHeader()->setStretchLastSection(true);
    horizontalHeader()->setHighlightSections(false);
    horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    setContextMenuPolicy(Qt::ActionsContextMenu);

    QPalette colors = palette();
    colors.setColor(QPalette::Base, theme::Background);
    colors.setColor(QPalette::AlternateBase, theme::Background);
    colors.setColor(QPalette::Text, theme::Text);
    colors.setColor(QPalette::Highlight, theme::Selection);
    colors.setColor(QPalette::HighlightedText, theme::Text);
    setPalette(colors);

    connect(this, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (QTableWidgetItem* first = item(row, 0))
            emit rowActivated(first->data(Qt::UserRole).toULongLong());
    });
}

void TableView::setRows(const QList<QStringList>& rows, const QList<std::uint64_t>& keys, const QList<bool>& emphasized)
{
    const std::uint64_t selected = currentKey();
    setUpdatesEnabled(false);
    setRowCount(int(rows.size()));
    for (int r = 0; r < rows.size(); ++r) {
        QFont rowFont = font();
        rowFont.setBold(r < emphasized.size() && emphasized[r]);
        for (int c = 0; c < columnCount(); ++c) {
            QTableWidgetItem* cell = item(r, c);
            if (!cell) {
                cell = new QTableWidgetItem;
                setItem(r, c, cell);
            }
            cell->setText(c < rows[r].size() ? rows[r][c] : QString());
            cell->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
            cell->setData(Qt::CheckStateRole, QVariant());
            cell->setFont(rowFont);
        }
        const std::uint64_t key = r < keys.size() ? keys[r] : NoKey;
        item(r, 0)->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(key));
        if (key == selected && key != NoKey)
            setCurrentCell(r, 0);
    }
    // Fit columns to addresses and labels; the last column stretches to the edge.
    for (int c = 0; c + 1 < columnCount(); ++c) {
        resizeColumnToContents(c);
        setColumnWidth(c, qMin(columnWidth(c) + fontMetrics().horizontalAdvance(QLatin1Char('0')) * 2, 480));
    }
    setUpdatesEnabled(true);
}

std::uint64_t TableView::currentKey() const
{
    const int row = currentRow();
    const QTableWidgetItem* first = row >= 0 ? item(row, 0) : nullptr;
    return first ? first->data(Qt::UserRole).toULongLong() : NoKey;
}

void TableView::addRowAction(const QKeySequence& key, const QString& text, std::function<void(std::uint64_t)> handler)
{
    auto* action = new QAction(text, this);
    action->setShortcut(key);
    action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    connect(action, &QAction::triggered, this, [this, text, handler] {
        static const bool trace = qEnvironmentVariableIsSet("CUTEGDB_UI_LOG");
        if (trace) {
            std::printf("[action] %s\n", qPrintable(QString(text).remove(QStringLiteral("..."))));
            std::fflush(stdout);
        }
        const std::uint64_t key = currentKey();
        if (key != NoKey)
            handler(key);
    });
    addAction(action);
}

BreakpointsView::BreakpointsView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_table = new TableView({tr("Type"), tr("Address"), tr("Label / Location"), tr("State"), tr("Hits"),
        tr("Condition"), tr("Log text")});
    fill(this, m_table);

    m_table->addRowAction(QKeySequence(Qt::Key_Delete), tr("Delete"),
        [this](std::uint64_t number) { m_session->deleteBreakpoint(std::uint32_t(number)); });
    m_table->addRowAction(QKeySequence(Qt::Key_Space), tr("Enable/Disable"), [this](std::uint64_t number) {
        if (const BreakpointRow* row = rowFor(number))
            m_session->setBreakpointEnabled(row->number, !row->enabled);
    });
    m_table->addRowAction(QKeySequence(QStringLiteral("Shift+F2")), tr("Edit condition..."), [this](std::uint64_t number) {
        const BreakpointRow* row = rowFor(number);
        if (!row)
            return;
        bool ok = false;
        const QString condition = QInputDialog::getText(this, tr("Edit breakpoint %1").arg(number),
            tr("Break condition (empty for none):"), QLineEdit::Normal, qs(row->condition), &ok);
        if (ok)
            m_session->setBreakpointCondition(std::uint32_t(number), condition);
    });
    auto follow = [this](std::uint64_t number) {
        if (const BreakpointRow* row = rowFor(number); row && row->has_address)
            emit followInDisassembler(row->address);
    };
    m_table->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow in Disassembler"), follow);
    connect(m_table, &TableView::rowActivated, this, follow);
    connect(session, &DebugSession::breakpointsChanged, this, &BreakpointsView::refresh);
    connect(session, &DebugSession::symbolsChanged, this, &BreakpointsView::refresh);
}

const BreakpointRow* BreakpointsView::rowFor(std::uint64_t number) const
{
    for (const BreakpointRow& row : m_rows) {
        if (row.number == number)
            return &row;
    }
    return nullptr;
}

void BreakpointsView::refresh()
{
    m_rows = m_session->breakpointRows();
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    for (const BreakpointRow& row : m_rows) {
        const QString label = qs(row.label);
        rows << QStringList{
            qs(row.kind),
            row.has_address ? m_session->formatAddress(row.address) : QString(),
            label.isEmpty() ? qs(row.location) : label,
            row.enabled ? tr("Enabled") : tr("Disabled"),
            QString::number(row.hits),
            qs(row.condition),
            qs(row.log_text),
        };
        keys << row.number;
    }
    m_table->setRows(rows, keys);
}

InfoListView::InfoListView(Kind kind, DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_kind(kind)
    , m_session(session)
{
    QStringList headers;
    switch (kind) {
    case CallStack:
        headers = {tr("#"), tr("Address"), tr("To"), tr("Source")};
        break;
    case Threads:
        headers = {tr("Number"), tr("ID"), tr("Name"), tr("Address"), tr("Label"), tr("State")};
        break;
    case MemoryMap:
        headers = {tr("Address"), tr("Size"), tr("Protection"), tr("Info")};
        break;
    case Handles:
        headers = {tr("FD"), tr("Target")};
        break;
    }
    m_table = new TableView(headers);
    fill(this, m_table);

    connect(m_table, &TableView::rowActivated, this, [this](std::uint64_t key) {
        switch (m_kind) {
        case CallStack:
            emit followInDisassembler(key);
            break;
        case Threads:
            m_session->selectThread(std::uint32_t(key));
            break;
        case MemoryMap:
            emit followInDump(key);
            break;
        case Handles:
            break;
        }
    });
    if (kind == CallStack)
        m_table->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow in Disassembler"),
            [this](std::uint64_t address) { emit followInDisassembler(address); });
    if (kind == MemoryMap)
        m_table->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow in Dump"),
            [this](std::uint64_t address) { emit followInDump(address); });
    if (kind == Threads)
        m_table->addRowAction(QKeySequence(Qt::Key_Return), tr("Switch Thread"),
            [this](std::uint64_t id) { m_session->selectThread(std::uint32_t(id)); });

    connect(session, &DebugSession::viewsChanged, this, &InfoListView::refresh);
    connect(session, &DebugSession::symbolsChanged, this, &InfoListView::refresh);
}

void InfoListView::refresh()
{
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    QList<bool> emphasized;
    switch (m_kind) {
    case CallStack:
        for (const FrameRow& row : m_session->frameRows()) {
            rows << QStringList{QString::number(row.level), m_session->formatAddress(row.address), qs(row.label), qs(row.source)};
            keys << row.address;
        }
        break;
    case Threads:
        for (const ThreadRow& row : m_session->threadRows()) {
            rows << QStringList{QString::number(row.id), QString::number(row.lwp), qs(row.name),
                m_session->formatAddress(row.address), qs(row.label), row.running ? tr("Running") : tr("Suspended")};
            keys << row.id;
            emphasized << row.current;
        }
        break;
    case MemoryMap:
        for (const MapRow& row : m_session->memoryMapRows()) {
            rows << QStringList{m_session->formatAddress(row.start), m_session->formatAddress(row.size), qs(row.perms), qs(row.info)};
            keys << row.start;
        }
        break;
    case Handles:
        for (const HandleRow& row : m_session->handleRows()) {
            rows << QStringList{QString::number(row.fd), qs(row.target)};
            keys << row.fd;
        }
        break;
    }
    m_table->setRows(rows, keys, emphasized);
}

SignalsView::SignalsView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_table = new TableView({tr("Signal"), tr("Stop"), tr("Print"), tr("Pass"), tr("Description")});
    fill(this, m_table);
    connect(session, &DebugSession::viewsChanged, this, &SignalsView::refresh);
    connect(m_table, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* changed) {
        if (m_updating || changed->column() < 1 || changed->column() > 3)
            return;
        const int row = changed->row();
        if (row < 0 || std::size_t(row) >= m_rows.size())
            return;
        const auto checked = [this, row](int column) { return m_table->item(row, column)->checkState() == Qt::Checked; };
        m_session->setSignalHandling(qs(m_rows[std::size_t(row)].name), checked(1), checked(2), checked(3));
    });
}

void SignalsView::refresh()
{
    m_rows = m_session->signalRows();
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    for (std::size_t i = 0; i < m_rows.size(); ++i) {
        rows << QStringList{qs(m_rows[i].name), QString(), QString(), QString(), qs(m_rows[i].description)};
        keys << i;
    }
    m_updating = true;
    m_table->setRows(rows, keys);
    for (std::size_t i = 0; i < m_rows.size(); ++i) {
        const bool flags[] = {m_rows[i].stop, m_rows[i].print, m_rows[i].pass};
        for (int c = 0; c < 3; ++c) {
            QTableWidgetItem* cell = m_table->item(int(i), c + 1);
            cell->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsUserCheckable);
            cell->setCheckState(flags[c] ? Qt::Checked : Qt::Unchecked);
        }
    }
    m_updating = false;
}

ReferencesView::ReferencesView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_title = new QLabel(tr("No search results"));
    m_table = new TableView({tr("Address"), tr("Disassembly"), tr("Info")});
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 2, 0, 0);
    layout->setSpacing(2);
    layout->addWidget(m_title);
    layout->addWidget(m_table);
    setFocusProxy(m_table);

    auto follow = [this](std::uint64_t address) { emit followInDisassembler(address); };
    connect(m_table, &TableView::rowActivated, this, follow);
    m_table->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow in Disassembler"), follow);
    connect(session, &DebugSession::referencesChanged, this, [this](QString title) {
        m_title->setText(title);
        refresh();
    });
    // Disassembly text appears once the referenced pages have been fetched.
    connect(session, &DebugSession::memoryChanged, this, [this] {
        if (isVisible())
            refresh();
    });
}

void ReferencesView::refresh()
{
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    for (const ReferenceRow& row : m_session->referenceRows()) {
        rows << QStringList{m_session->formatAddress(row.address), qs(row.disassembly), qs(row.info)};
        keys << row.address;
    }
    m_table->setRows(rows, keys);
}

namespace {

void traceUi(const QString& name)
{
    static const bool trace = qEnvironmentVariableIsSet("CUTEGDB_UI_LOG");
    if (trace) {
        std::printf("[action] %s\n", qPrintable(name));
        std::fflush(stdout);
    }
}

} // namespace

TraceView::TraceView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_title = new QLabel(tr("No trace recorded"));
    auto* exportButton = new QPushButton(tr("&Export..."));
    auto* header = new QHBoxLayout;
    header->addWidget(m_title, 1);
    header->addWidget(exportButton);
    m_table = new TableView({tr("Address"), tr("Bytes"), tr("Disassembly"), tr("Changed registers")});
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 2, 0, 0);
    layout->setSpacing(2);
    layout->addLayout(header);
    layout->addWidget(m_table);
    setFocusProxy(m_table);

    auto follow = [this](std::uint64_t address) { emit followInDisassembler(address); };
    connect(m_table, &TableView::rowActivated, this, follow);
    m_table->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow in Disassembler"), follow);
    connect(exportButton, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getSaveFileName(this, tr("Export trace"), QString(), QString(), nullptr,
            QFileDialog::DontUseNativeDialog);
        if (!path.isEmpty())
            m_session->exportTrace(path);
    });
    connect(session, &DebugSession::traceChanged, this, &TraceView::refresh);
}

void TraceView::refresh()
{
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    for (const TraceRow& row : m_session->traceRows()) {
        rows << QStringList{m_session->formatAddress(row.address), qs(row.bytes), qs(row.text), qs(row.changes)};
        keys << row.address;
    }
    m_title->setText(tr("%n traced instruction(s)", nullptr, int(rows.size())));
    m_table->setRows(rows, keys);
    traceUi(QStringLiteral("Trace view: %1 row(s)").arg(rows.size()));
}

GraphView::GraphView(DebugSession* session, QWidget* parent)
    : QGraphicsView(parent)
    , m_session(session)
    , m_scene(new QGraphicsScene(this))
{
    setScene(m_scene);
    setRenderHint(QPainter::Antialiasing);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setBackgroundBrush(theme::Background);
    connect(session, &DebugSession::memoryChanged, this, [this] {
        if (m_loaded && isVisible())
            rebuild();
    });
}

void GraphView::showFunction(std::uint64_t address)
{
    m_address = address;
    m_loaded = true;
    rebuild();
    if (!m_scene->items().isEmpty())
        centerOn(m_scene->itemsBoundingRect().center().x(), m_scene->itemsBoundingRect().top());
}

void GraphView::rebuild()
{
    const auto blocks = m_session->functionGraph(m_address);
    m_scene->clear();
    if (blocks.empty())
        return;

    const QFont font = theme::monospaceFont();
    const QFontMetrics metrics(font);
    const std::uint64_t cip = m_session->currentAddress();
    QHash<std::uint64_t, int> indexOf;
    for (std::size_t i = 0; i < blocks.size(); ++i)
        indexOf.insert(blocks[i].start, int(i));

    // Layers by breadth-first order from the entry block (always first).
    QVector<int> layer(int(blocks.size()), -1);
    QList<int> queue{0};
    layer[0] = 0;
    while (!queue.isEmpty()) {
        const int current = queue.takeFirst();
        for (const std::uint64_t target : blocks[std::size_t(current)].edge_targets) {
            const int next = indexOf.value(target, -1);
            if (next >= 0 && layer[next] < 0) {
                layer[next] = layer[current] + 1;
                queue << next;
            }
        }
    }
    int maxLayer = 0;
    for (int& l : layer) {
        if (l < 0)
            l = ++maxLayer;
        maxLayer = qMax(maxLayer, l);
    }

    const int padding = 6;
    const int gapX = 40;
    const int gapY = 60;
    QVector<QRectF> rects(int(blocks.size()));
    QVector<int> layerWidth(maxLayer + 1, 0);
    QVector<int> layerHeight(maxLayer + 1, 0);
    QVector<QSize> sizes(int(blocks.size()));
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const QSize size = metrics.size(0, qs(blocks[i].text)) + QSize(2 * padding, 2 * padding);
        sizes[int(i)] = size;
        const int l = layer[int(i)];
        layerWidth[l] += size.width() + (layerWidth[l] > 0 ? gapX : 0);
        layerHeight[l] = qMax(layerHeight[l], size.height());
    }
    QVector<int> cursorX(maxLayer + 1, 0);
    int y = 0;
    QVector<int> layerY(maxLayer + 1, 0);
    for (int l = 0; l <= maxLayer; ++l) {
        layerY[l] = y;
        y += layerHeight[l] + gapY;
        cursorX[l] = -layerWidth[l] / 2;
    }
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const int l = layer[int(i)];
        rects[int(i)] = QRectF(cursorX[l], layerY[l], sizes[int(i)].width(), sizes[int(i)].height());
        cursorX[l] += sizes[int(i)].width() + gapX;
    }

    static const QColor edgeColors[] = {QColor(0x00, 0x00, 0xff), QColor(0x00, 0x80, 0x00), QColor(0xff, 0x00, 0x00)};
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const auto& block = blocks[i];
        for (std::size_t e = 0; e < block.edge_targets.size(); ++e) {
            const int target = indexOf.value(block.edge_targets[e], -1);
            if (target < 0)
                continue;
            const QColor color = edgeColors[qMin<int>(block.edge_kinds[e], 2)];
            const QPointF from(rects[int(i)].center().x(), rects[int(i)].bottom());
            const QPointF to(rects[target].center().x(), rects[target].top());
            QPainterPath path(from);
            if (layer[target] > layer[int(i)]) {
                path.cubicTo(from + QPointF(0, gapY / 2.0), to - QPointF(0, gapY / 2.0), to);
            } else {
                // Back edge (loop): leave downwards, run up beside both blocks, enter the target from above.
                const qreal side = qMin(rects[int(i)].left(), rects[target].left()) - gapX / 2.0;
                path.lineTo(from + QPointF(0, gapY / 3.0));
                path.lineTo(side, from.y() + gapY / 3.0);
                path.lineTo(side, to.y() - gapY / 3.0);
                path.lineTo(to - QPointF(0, gapY / 3.0));
                path.lineTo(to);
            }
            m_scene->addPath(path, QPen(color, 1.5));
            m_scene->addPolygon(QPolygonF({to, to + QPointF(-4, -8), to + QPointF(4, -8)}), QPen(color), QBrush(color));
        }
    }
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const auto& block = blocks[i];
        const bool containsCip = qs(block.text).contains(m_session->formatAddress(cip));
        auto* rect = m_scene->addRect(rects[int(i)], QPen(Qt::black, containsCip ? 2.5 : 1), QBrush(theme::Background));
        rect->setData(0, QVariant::fromValue<qulonglong>(block.start));
        auto* text = m_scene->addSimpleText(qs(block.text), font);
        text->setBrush(theme::Text);
        text->setPos(rects[int(i)].topLeft() + QPointF(padding, padding));
        text->setParentItem(rect);
        text->setPos(rects[int(i)].topLeft() + QPointF(padding, padding) - rect->pos());
    }
    m_scene->setSceneRect(m_scene->itemsBoundingRect().adjusted(-40, -40, 40, 40));
}

void GraphView::mouseDoubleClickEvent(QMouseEvent* event)
{
    for (QGraphicsItem* item = itemAt(event->pos()); item; item = item->parentItem()) {
        const QVariant start = item->data(0);
        if (start.isValid()) {
            emit followInDisassembler(start.toULongLong());
            return;
        }
    }
    QGraphicsView::mouseDoubleClickEvent(event);
}

void GraphView::wheelEvent(QWheelEvent* event)
{
    if (event->modifiers() & Qt::ControlModifier) {
        const double factor = event->angleDelta().y() > 0 ? 1.15 : 1 / 1.15;
        scale(factor, factor);
        event->accept();
        return;
    }
    QGraphicsView::wheelEvent(event);
}

ScriptView::ScriptView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_editor = new QPlainTextEdit;
    m_editor->setFont(theme::monospaceFont());
    m_editor->setPlaceholderText(tr("Type a script, or press Ctrl+O to open one. Ctrl+L loads the text below."));
    m_status = new QLabel(tr("No script loaded"));
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 2, 0, 0);
    layout->setSpacing(2);
    layout->addWidget(m_status);
    layout->addWidget(m_editor);
    setFocusPolicy(Qt::StrongFocus);

    const auto add = [this](const char* key, const QString& text, std::function<void()> handler) {
        auto* action = new QAction(text, this);
        action->setShortcut(QKeySequence(QString::fromLatin1(key)));
        action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
        connect(action, &QAction::triggered, this, handler);
        addAction(action);
    };
    add("Ctrl+O", tr("Open"), [this] {
        const QString path = QFileDialog::getOpenFileName(this, tr("Open script"), QString(),
            tr("Scripts (*.txt *.x64dbg);;All files (*)"), nullptr, QFileDialog::DontUseNativeDialog);
        if (path.isEmpty())
            return;
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            m_status->setText(tr("Cannot open %1").arg(path));
            return;
        }
        m_editor->setPlainText(QString::fromUtf8(file.readAll()));
        m_path = path;
        loadText(m_editor->toPlainText());
    });
    add("Ctrl+L", tr("Load"), [this] { loadText(m_editor->toPlainText()); });
    add("Ctrl+R", tr("Reload"), [this] {
        QFile file(m_path);
        if (!m_path.isEmpty() && file.open(QIODevice::ReadOnly)) {
            m_editor->setPlainText(QString::fromUtf8(file.readAll()));
            loadText(m_editor->toPlainText());
        }
    });
    add("Ctrl+U", tr("Unload"), [this] { setLoaded(false); });
    add("Space", tr("Run"), [this] {
        if (m_loaded)
            m_session->runScript(false);
    });
    add("Tab", tr("Step"), [this] {
        if (m_loaded)
            m_session->runScript(true);
    });
    add("Esc", tr("Abort"), [this] { m_session->abortScript(); });
    connect(session, &DebugSession::scriptStateChanged, this, &ScriptView::highlight);
}

bool ScriptView::loadText(const QString& text)
{
    const QString error = m_session->loadScript(text);
    if (!error.isEmpty()) {
        m_status->setText(tr("Script error: %1").arg(error));
        return false;
    }
    setLoaded(true);
    traceUi(QStringLiteral("Script loaded"));
    return true;
}

void ScriptView::setLoaded(bool loaded)
{
    m_loaded = loaded;
    // While loaded the script is read-only and keys go to the run/step actions, as in x64dbg.
    m_editor->setReadOnly(loaded);
    m_editor->setFocusPolicy(loaded ? Qt::NoFocus : Qt::StrongFocus);
    if (loaded) {
        setFocus();
        m_status->setText(tr("Loaded: Space runs, Tab steps, Esc aborts, Ctrl+U edits"));
    } else {
        m_editor->setExtraSelections({});
        m_editor->setFocus();
        m_status->setText(tr("Editing"));
    }
}

void ScriptView::highlight(int line, bool running)
{
    if (!m_loaded)
        return;
    QList<QTextEdit::ExtraSelection> selections;
    const QTextBlock block = m_editor->document()->findBlockByNumber(line);
    if (line >= 0 && block.isValid()) {
        QTextEdit::ExtraSelection selection;
        selection.format.setBackground(running ? QColor(0xff, 0xff, 0x00) : theme::Selection);
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = QTextCursor(block);
        selections << selection;
        m_editor->setTextCursor(QTextCursor(block));
    }
    m_editor->setExtraSelections(selections);
    m_status->setText(running ? tr("Running line %1").arg(line + 1)
                              : (block.isValid() ? tr("Paused before line %1").arg(line + 1) : tr("Finished")));
}

SymbolsView::SymbolsView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    m_modules = new TableView({tr("Base"), tr("Module"), tr("Size"), tr("Path")});
    m_symbols = new TableView({tr("Address"), tr("Symbol"), tr("Size")});
    m_filter = new QLineEdit;
    m_filter->setPlaceholderText(tr("Search"));

    auto* symbolsPane = new QWidget;
    auto* symbolsLayout = new QVBoxLayout(symbolsPane);
    symbolsLayout->setContentsMargins(0, 0, 0, 0);
    symbolsLayout->setSpacing(0);
    symbolsLayout->addWidget(m_symbols);
    symbolsLayout->addWidget(m_filter);

    auto* splitter = new QSplitter(Qt::Horizontal);
    splitter->addWidget(m_modules);
    splitter->addWidget(symbolsPane);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    fill(this, splitter);
    setFocusProxy(m_modules);

    connect(m_modules, &QTableWidget::currentCellChanged, this, [this] { refreshSymbols(); });
    connect(m_filter, &QLineEdit::textChanged, this, [this] { refreshSymbols(); });
    connect(m_symbols, &TableView::rowActivated, this, &SymbolsView::followInDisassembler);
    m_symbols->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow in Disassembler"),
        [this](std::uint64_t address) { emit followInDisassembler(address); });
    m_modules->addRowAction(QKeySequence(Qt::Key_Return), tr("Follow Entry Point"), [this](std::uint64_t base) {
        for (const ModuleRow& row : m_moduleRows) {
            if (row.base == base && row.entry != 0)
                emit followInDisassembler(row.entry);
        }
    });
    connect(session, &DebugSession::symbolsChanged, this, &SymbolsView::refreshModules);
}

void SymbolsView::refreshModules()
{
    m_moduleRows = m_session->moduleRows();
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    for (const ModuleRow& row : m_moduleRows) {
        rows << QStringList{m_session->formatAddress(row.base), qs(row.name), hex(row.size), qs(row.path)};
        keys << row.base;
    }
    m_modules->setRows(rows, keys);
    if (m_modules->currentRow() < 0 && !m_moduleRows.empty())
        m_modules->setCurrentCell(0, 0);
    refreshSymbols();
}

void SymbolsView::refreshSymbols()
{
    const int module = m_modules->currentRow();
    QList<QStringList> rows;
    QList<std::uint64_t> keys;
    if (module >= 0 && std::size_t(module) < m_moduleRows.size()) {
        const QString filter = m_filter->text().trimmed();
        for (const SymbolRow& row : m_session->symbolRows(qs(m_moduleRows[std::size_t(module)].name))) {
            const QString name = qs(row.name);
            if (!filter.isEmpty() && !name.contains(filter, Qt::CaseInsensitive))
                continue;
            rows << QStringList{m_session->formatAddress(row.address), name, hex(row.size)};
            keys << row.address;
        }
    }
    m_symbols->setRows(rows, keys);
}
