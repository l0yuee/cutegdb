#include "disassemblyview.h"
#include "theme.h"

#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>

namespace {

// Mirrors kind_code() in session.rs.
enum Kind : std::uint8_t {
    Normal = 0,
    Call = 1,
    Jump = 2,
    ConditionalJump = 3,
    Ret = 4,
    Interrupt = 5,
    Nop = 6,
    PushPop = 7,
    Unknown = 255,
};

bool isBranch(const DisasmRow& row)
{
    return row.has_target && (row.kind == Jump || row.kind == ConditionalJump);
}

} // namespace

DisassemblyView::DisassemblyView(DebugSession* session, QWidget* parent)
    : BaseView(session, parent)
{
    addViewAction(QKeySequence(Qt::Key_F2), [this] {
        if (m_loaded)
            this->session()->toggleBreakpoint(m_selection);
    });
    addViewAction(QKeySequence(QStringLiteral("Shift+F2")), [this] {
        if (m_loaded)
            emit editBreakpointRequested(m_selection);
    });
    addViewAction(QKeySequence(Qt::Key_Space), [this] {
        if (rowIndex(m_selection) >= 0)
            emit assembleRequested(m_selection, selectedInstructionText());
    });
    addViewAction(QKeySequence(QStringLiteral("Ctrl+B")), [this] {
        if (m_loaded)
            emit searchPatternRequested(m_selection);
    });
    addViewAction(QKeySequence(QStringLiteral("Ctrl+D")), [this] {
        if (m_loaded)
            this->session()->toggleBookmark(m_selection);
    });
    addViewAction(QKeySequence(QStringLiteral("Ctrl+E")), [this] {
        const int index = rowIndex(m_selection);
        if (index >= 0)
            emit binaryEditRequested(m_selection, int(m_rows[std::size_t(index)].size));
    });
    addViewAction(QKeySequence(Qt::Key_Return), [this] { followBranch(); });
    addViewAction(QKeySequence(Qt::Key_Enter), [this] { followBranch(); });
}

void DisassemblyView::gotoAddress(std::uint64_t address, bool recordHistory)
{
    if (recordHistory && m_loaded && m_selection != address) {
        m_back.push_back(m_selection);
        m_forward.clear();
    }
    m_top = address;
    m_loaded = true;
    reload();
    select(address);
}

void DisassemblyView::followCip(std::uint64_t cip)
{
    const int index = rowIndex(cip);
    if (!m_loaded || index < 0 || index >= visibleRows() - 1)
        m_top = cip;
    m_loaded = true;
    reload();
    select(cip);
}

void DisassemblyView::reload()
{
    if (!m_loaded)
        return;
    m_rows = session()->disassemble(m_top, visibleRows() + 1);
    viewport()->update();
}

void DisassemblyView::select(std::uint64_t address)
{
    m_selection = address;
    viewport()->update();
    emit selectionChanged(address);
}

int DisassemblyView::rowIndex(std::uint64_t address) const
{
    for (std::size_t i = 0; i < m_rows.size(); ++i) {
        if (m_rows[i].address == address)
            return int(i);
    }
    return -1;
}

int DisassemblyView::sidebarWidth() const
{
    return charWidth() * 6;
}

QString DisassemblyView::selectedInstructionText() const
{
    const int index = rowIndex(m_selection);
    if (index < 0)
        return QString();
    const DisasmRow& row = m_rows[std::size_t(index)];
    const QString operands = qs(row.operands);
    return operands.isEmpty() ? qs(row.mnemonic) : qs(row.mnemonic) + QLatin1Char(' ') + operands;
}

int DisassemblyView::selectedInstructionSize() const
{
    const int index = rowIndex(m_selection);
    return index < 0 ? 1 : int(m_rows[std::size_t(index)].size);
}

void DisassemblyView::contextMenuEvent(QContextMenuEvent* event)
{
    if (!m_loaded)
        return;
    const int row = event->pos().y() / rowHeight();
    if (row >= 0 && std::size_t(row) < m_rows.size())
        select(m_rows[std::size_t(row)].address);
    const std::uint64_t address = m_selection;

    QMenu menu(this);
    const auto add = [](QMenu* target, const QString& text, const char* key, std::function<void()> handler) {
        QAction* action = target->addAction(text);
        if (key)
            action->setShortcut(QKeySequence(QString::fromLatin1(key)));
        QObject::connect(action, &QAction::triggered, handler);
    };
    QMenu* breakpoint = menu.addMenu(tr("&Breakpoint"));
    add(breakpoint, tr("Toggle"), "F2", [this, address] { session()->toggleBreakpoint(address); });
    add(breakpoint, tr("Set Hardware on Execution"), nullptr, [this, address] { session()->setHardwareBreakpoint(address); });
    add(breakpoint, tr("Edit"), "Shift+F2", [this, address] { emit editBreakpointRequested(address); });
    menu.addSeparator();
    add(&menu, tr("&Assemble"), "Space", [this, address] { emit assembleRequested(address, selectedInstructionText()); });
    add(&menu, tr("&Edit binary"), "Ctrl+E", [this, address] { emit binaryEditRequested(address, selectedInstructionSize()); });
    add(&menu, tr("&Label"), ":", [this, address] { emit labelRequested(address); });
    add(&menu, tr("&Comment"), ";", [this, address] { emit commentRequested(address); });
    add(&menu, tr("Book&mark"), "Ctrl+D", [this, address] { session()->toggleBookmark(address); });
    menu.addSeparator();
    QMenu* search = menu.addMenu(tr("&Search for"));
    add(search, tr("Pattern"), "Ctrl+B", [this, address] { emit searchPatternRequested(address); });
    add(search, tr("String references"), nullptr, [this, address] { emit stringReferencesRequested(address); });
    add(&menu, tr("Find &references to selected address"), "X", [this, address] { emit referencesRequested(address); });
    add(&menu, tr("&Graph"), "G", [this, address] { emit graphRequested(address); });
    menu.addSeparator();
    QMenu* go = menu.addMenu(tr("&Go to"));
    add(go, tr("Origin"), "*", [this] { gotoAddress(session()->currentAddress(), true); });
    add(go, tr("Expression"), "Ctrl+G", [this] { emit gotoExpressionRequested(); });
    menu.exec(event->globalPos());
}

void DisassemblyView::scrollLines(int lines)
{
    if (!m_loaded || lines == 0)
        return;
    if (lines > 0) {
        const auto rows = session()->disassemble(m_top, lines + 1);
        if (rows.size() > std::size_t(lines))
            m_top = rows[std::size_t(lines)].address;
    } else {
        for (int i = 0; i < -lines; ++i)
            m_top = session()->previousInstruction(m_top);
    }
    reload();
}

void DisassemblyView::followBranch()
{
    const int index = rowIndex(m_selection);
    if (index >= 0 && m_rows[std::size_t(index)].has_target)
        gotoAddress(m_rows[std::size_t(index)].target, true);
}

void DisassemblyView::keyPressEvent(QKeyEvent* event)
{
    if (!m_loaded)
        return BaseView::keyPressEvent(event);
    const int index = rowIndex(m_selection);
    switch (event->key()) {
    case Qt::Key_Up:
        if (index > 0) {
            select(m_rows[std::size_t(index - 1)].address);
        } else {
            scrollLines(-1);
            select(m_top);
        }
        return;
    case Qt::Key_Down:
        if (index >= 0 && index + 1 < visibleRows()) {
            select(m_rows[std::size_t(index + 1)].address);
        } else {
            scrollLines(1);
            if (!m_rows.empty())
                select(m_rows[std::size_t(qMin<int>(visibleRows(), int(m_rows.size())) - 1)].address);
        }
        return;
    case Qt::Key_PageUp:
        scrollLines(-visibleRows());
        return;
    case Qt::Key_PageDown:
        scrollLines(visibleRows());
        return;
    default:
        break;
    }

    const QString text = event->text();
    if (text.compare(QLatin1String("x"), Qt::CaseInsensitive) == 0 && event->modifiers() == Qt::NoModifier) {
        emit referencesRequested(m_selection);
    } else if (text.compare(QLatin1String("g"), Qt::CaseInsensitive) == 0 && event->modifiers() == Qt::NoModifier) {
        emit graphRequested(m_selection);
    } else if (text == QLatin1String(";")) {
        emit commentRequested(m_selection);
    } else if (text == QLatin1String(":")) {
        emit labelRequested(m_selection);
    } else if (text == QLatin1String("*")) {
        gotoAddress(session()->currentAddress(), true);
    } else if (text == QLatin1String("-")) {
        if (!m_back.isEmpty()) {
            m_forward.push_back(m_selection);
            gotoAddress(m_back.takeLast(), false);
        }
    } else if (text == QLatin1String("+") || text == QLatin1String("=")) {
        if (!m_forward.isEmpty()) {
            m_back.push_back(m_selection);
            gotoAddress(m_forward.takeLast(), false);
        }
    } else {
        BaseView::keyPressEvent(event);
    }
}

void DisassemblyView::mousePressEvent(QMouseEvent* event)
{
    const int row = int(event->position().y()) / rowHeight();
    if (row < 0 || std::size_t(row) >= m_rows.size())
        return;
    const std::uint64_t address = m_rows[std::size_t(row)].address;
    // Clicking the bullet column toggles a breakpoint, as in x64dbg.
    if (event->position().x() < sidebarWidth() && event->button() == Qt::LeftButton)
        session()->toggleBreakpoint(address);
    select(address);
}

void DisassemblyView::resizeEvent(QResizeEvent* event)
{
    BaseView::resizeEvent(event);
    reload();
}

void DisassemblyView::paintEvent(QPaintEvent*)
{
    QPainter p(viewport());
    p.setFont(font());
    p.fillRect(viewport()->rect(), theme::Background);
    if (!m_loaded)
        return;

    const int rh = rowHeight();
    const int cw = charWidth();
    const int side = sidebarWidth();
    const int addressWidth = cw * (session()->pointerSize() * 2 + 2);
    const int bytesWidth = cw * 21;
    const int disassemblyWidth = cw * 44;
    const std::uint64_t cip = session()->currentAddress();
    const bool paused = session()->debugState() == 1;
    const int rows = qMin<int>(visibleRows(), int(m_rows.size()));
    const QFontMetrics metrics(font());

    for (int i = 0; i < rows; ++i) {
        const DisasmRow& row = m_rows[std::size_t(i)];
        const int y = i * rh;
        if (row.address == m_selection)
            p.fillRect(QRect(side, y, viewport()->width() - side, rh), theme::Selection);

        QRect addressRect(side, y, addressWidth, rh);
        QColor addressColor = theme::AddressText;
        if (paused && row.address == cip) {
            p.fillRect(addressRect, theme::CipBackground);
            addressColor = theme::CipText;
        } else if (const int state = session()->breakpointState(row.address); state == 1 || state == 3) {
            p.fillRect(addressRect, theme::BreakpointBackground);
            addressColor = theme::BreakpointText;
        }
        const QString label = qs(row.label);
        const QRect addressText = addressRect.adjusted(cw / 2, 0, -cw / 2, 0);
        p.setPen(addressColor);
        p.drawText(addressText, Qt::AlignVCenter | Qt::AlignLeft,
            label.isEmpty() ? session()->formatAddress(row.address)
                            : metrics.elidedText(label, Qt::ElideRight, addressText.width()));

        p.setPen(theme::BytesText);
        const QRect bytesRect(side + addressWidth, y, bytesWidth - cw, rh);
        p.drawText(bytesRect, Qt::AlignVCenter | Qt::AlignLeft,
            metrics.elidedText(qs(row.bytes), Qt::ElideRight, bytesRect.width()));

        int x = side + addressWidth + bytesWidth;
        const QString mnemonic = qs(row.mnemonic);
        const int mnemonicWidth = metrics.horizontalAdvance(mnemonic);
        QColor background;
        QColor foreground = theme::Text;
        switch (row.kind) {
        case Call:
            background = theme::CallBackground;
            break;
        case Jump:
        case ConditionalJump:
            background = theme::JumpBackground;
            break;
        case Ret:
            background = theme::RetBackground;
            break;
        case PushPop:
            foreground = theme::PushPopText;
            break;
        case Nop:
            foreground = theme::NopText;
            break;
        case Unknown:
            foreground = theme::Unreadable;
            break;
        default:
            break;
        }
        if (background.isValid())
            p.fillRect(QRect(x, y + 1, mnemonicWidth, rh - 2), background);
        p.setPen(foreground);
        p.drawText(QRect(x, y, mnemonicWidth, rh), Qt::AlignVCenter | Qt::AlignLeft, mnemonic);
        p.setPen(theme::Text);
        p.drawText(QRect(x + mnemonicWidth + cw, y, disassemblyWidth - mnemonicWidth - cw, rh),
            Qt::AlignVCenter | Qt::AlignLeft, qs(row.operands));

        x = side + addressWidth + bytesWidth + disassemblyWidth;
        p.drawText(QRect(x, y, viewport()->width() - x, rh), Qt::AlignVCenter | Qt::AlignLeft, qs(row.comment));
    }
    paintSidebar(p, rows, cip, paused);
}

void DisassemblyView::paintSidebar(QPainter& p, int rows, std::uint64_t cip, bool paused)
{
    if (rows == 0)
        return;
    const int rh = rowHeight();
    const int side = sidebarWidth();
    p.save();
    p.setRenderHint(QPainter::Antialiasing);
    int lane = 0;
    for (int i = 0; i < rows; ++i) {
        const DisasmRow& row = m_rows[std::size_t(i)];
        const int cy = i * rh + rh / 2;
        if (const int state = session()->breakpointState(row.address); state != 0) {
            p.setPen(Qt::NoPen);
            p.setBrush(state == 2 ? theme::DisabledBreakpoint
                                  : state == 3 ? theme::HardwareBreakpoint : theme::BreakpointBackground);
            p.drawEllipse(QPoint(rh / 2, cy), rh / 4, rh / 4);
        }
        if (session()->isBookmarked(row.address)) {
            p.setPen(Qt::NoPen);
            p.setBrush(theme::Bookmark);
            p.drawRect(QRect(1, cy - rh / 4, rh / 5, rh / 2));
        }
        if (paused && row.address == cip) {
            const int left = rh;
            const QPolygon arrow({QPoint(left, cy - rh / 4), QPoint(left + rh / 2, cy), QPoint(left, cy + rh / 4)});
            p.setPen(Qt::NoPen);
            p.setBrush(theme::CipBackground);
            p.drawPolygon(arrow);
        }
        if (!isBranch(row))
            continue;

        int targetRow = -1;
        for (int j = 0; j < rows; ++j) {
            if (m_rows[std::size_t(j)].address == row.target)
                targetRow = j;
        }
        int targetY;
        if (targetRow >= 0)
            targetY = targetRow * rh + rh / 2;
        else if (row.target < m_rows[0].address)
            targetY = 0;
        else if (row.target > m_rows[std::size_t(rows - 1)].address)
            targetY = rows * rh;
        else
            continue; // lands inside a visible instruction
        const int x = side - 4 - (lane++ % 4) * 4;
        const QColor color = row.address == m_selection ? theme::SelectedJumpLine : theme::JumpLine;
        p.setPen(QPen(color, 1));
        p.setBrush(Qt::NoBrush);
        p.drawLine(side - 1, cy, x, cy);
        p.drawLine(x, cy, x, targetY);
        if (targetRow >= 0) {
            p.drawLine(x, targetY, side - 1, targetY);
            p.setPen(Qt::NoPen);
            p.setBrush(color);
            p.drawPolygon(QPolygon({QPoint(side - 1, targetY), QPoint(side - 5, targetY - 3), QPoint(side - 5, targetY + 3)}));
        }
    }
    p.restore();
}
