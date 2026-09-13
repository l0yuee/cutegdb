#include "registersview.h"
#include "theme.h"

#include <QPainter>

namespace {

// How each register group is laid out: entries per line and the width reserved for names.
struct GroupLayout {
    int perLine;
    int nameChars;
    int cellChars;
};

GroupLayout layoutFor(int group)
{
    switch (group) {
    case 2: // flag bits
        return {3, 3, 6};
    case 3: // segments
        return {2, 3, 10};
    default:
        return {1, 7, 0};
    }
}

} // namespace

RegistersView::RegistersView(DebugSession* session, QWidget* parent)
    : QWidget(parent)
    , m_session(session)
{
    setFont(theme::monospaceFont());
    setAutoFillBackground(false);
}

void RegistersView::refresh()
{
    m_rows = m_session->registers();
    update();
}

void RegistersView::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.fillRect(rect(), theme::Background);
    p.setFont(font());
    const QFontMetrics metrics(font());
    const int rh = metrics.height() + 2;
    const int cw = metrics.horizontalAdvance(QLatin1Char('0'));

    int y = 4;
    int column = 0;
    int lastGroup = -1;
    for (const RegisterRow& row : m_rows) {
        const int group = row.group;
        if (group != lastGroup) {
            if (lastGroup != -1) {
                if (column != 0)
                    y += rh;
                y += rh / 2;
            }
            column = 0;
            lastGroup = group;
        }
        const GroupLayout layout = layoutFor(group);
        const int x = 6 + column * layout.cellChars * cw;
        const QString value = qs(row.value);

        p.setPen(theme::Text);
        p.drawText(x, y, layout.nameChars * cw, rh, Qt::AlignVCenter | Qt::AlignLeft, qs(row.name));
        const int valueX = x + layout.nameChars * cw;
        p.setPen(row.changed ? theme::ChangedText : theme::Text);
        p.drawText(valueX, y, width() - valueX, rh, Qt::AlignVCenter | Qt::AlignLeft, value);
        if (!row.comment.empty()) {
            const int commentX = valueX + (value.size() + 2) * cw;
            p.setPen(theme::Text);
            p.drawText(commentX, y, width() - commentX, rh, Qt::AlignVCenter | Qt::AlignLeft,
                QStringLiteral("<%1>").arg(qs(row.comment)));
        }
        if (++column == layout.perLine) {
            column = 0;
            y += rh;
        }
    }
    if (column != 0)
        y += rh;

    const int height = y + 4;
    if (minimumHeight() != height)
        setMinimumHeight(height);
}
