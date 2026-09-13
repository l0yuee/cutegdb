#include "stackview.h"
#include "theme.h"

#include <QKeyEvent>
#include <QPainter>

StackView::StackView(DebugSession* session, QWidget* parent)
    : BaseView(session, parent)
{
}

void StackView::gotoAddress(std::uint64_t address)
{
    m_top = address;
    m_loaded = true;
    reload();
}

void StackView::followStackPointer(std::uint64_t sp)
{
    const std::uint64_t size = std::uint64_t(session()->pointerSize());
    const std::uint64_t end = m_top + std::uint64_t(visibleRows()) * size;
    if (!m_loaded || sp < m_top || sp >= end)
        m_top = sp;
    m_loaded = true;
    reload();
}

void StackView::reload()
{
    if (!m_loaded)
        return;
    m_rows = session()->stackRows(m_top, visibleRows());
    viewport()->update();
}

void StackView::scrollLines(int lines)
{
    if (!m_loaded)
        return;
    m_top += std::uint64_t(std::int64_t(lines) * session()->pointerSize());
    reload();
}

void StackView::keyPressEvent(QKeyEvent* event)
{
    switch (event->key()) {
    case Qt::Key_Up:
        scrollLines(-1);
        break;
    case Qt::Key_Down:
        scrollLines(1);
        break;
    case Qt::Key_PageUp:
        scrollLines(-visibleRows());
        break;
    case Qt::Key_PageDown:
        scrollLines(visibleRows());
        break;
    default:
        BaseView::keyPressEvent(event);
    }
}

void StackView::resizeEvent(QResizeEvent* event)
{
    BaseView::resizeEvent(event);
    reload();
}

void StackView::paintEvent(QPaintEvent*)
{
    QPainter p(viewport());
    p.setFont(font());
    p.fillRect(viewport()->rect(), theme::Background);
    if (!m_loaded)
        return;

    const int rh = rowHeight();
    const int cw = charWidth();
    const int columnWidth = cw * (session()->pointerSize() * 2 + 2);
    const std::uint64_t sp = session()->stackPointer();
    const bool paused = session()->debugState() == 1;

    for (std::size_t i = 0; i < m_rows.size(); ++i) {
        const StackRow& row = m_rows[i];
        const int y = int(i) * rh;
        QRect addressRect(0, y, columnWidth, rh);
        if (paused && row.address == sp) {
            p.fillRect(addressRect, theme::CipBackground);
            p.setPen(theme::CipText);
        } else {
            p.setPen(theme::AddressText);
        }
        p.drawText(addressRect.adjusted(cw / 2, 0, 0, 0), Qt::AlignVCenter | Qt::AlignLeft,
            session()->formatAddress(row.address));

        p.setPen(row.readable ? theme::Text : theme::Unreadable);
        const QString value = row.readable ? session()->formatAddress(row.value)
                                           : QString(session()->pointerSize() * 2, QLatin1Char('?'));
        p.drawText(QRect(columnWidth, y, columnWidth, rh), Qt::AlignVCenter | Qt::AlignLeft, value);

        p.setPen(theme::Text);
        p.drawText(QRect(columnWidth * 2, y, viewport()->width() - columnWidth * 2, rh),
            Qt::AlignVCenter | Qt::AlignLeft, qs(row.comment));
    }
}
