#include "app.h"
#include "mainwindow.h"

#include <QApplication>
#include <string>
#include <vector>

int run_app(rust::Vec<rust::String> args)
{
    // QApplication keeps references to argc/argv for its whole lifetime.
    static std::vector<std::string> storage;
    static std::vector<char*> argv;
    static int argc = 0;
    for (const auto& a : args)
        storage.emplace_back(std::string(a));
    for (auto& s : storage)
        argv.push_back(s.data());
    argv.push_back(nullptr);
    argc = int(storage.size());

    QApplication app(argc, argv.data());
    QApplication::setApplicationName(QStringLiteral("cutegdb"));
    QApplication::setOrganizationName(QStringLiteral("cutegdb"));

    QString screenshot;
    QStringList positional;
    const QStringList list = QApplication::arguments();
    for (int i = 1; i < list.size(); ++i) {
        if (list[i] == QLatin1String("--smoke-test") && i + 1 < list.size())
            screenshot = list[++i];
        else
            positional << list[i];
    }

    MainWindow window;
    window.show();
    if (!positional.isEmpty())
        window.openExecutable(positional.first());
    if (!screenshot.isEmpty())
        window.runSmokeTest(screenshot);
    return app.exec();
}
