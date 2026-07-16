// Standalone Qt dialog helper for agent-sandbox policy prompts.
// No KDE or GTK dependencies, just Qt Widgets.
#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QFormLayout>
#include <QFrame>
#include <QGroupBox>
#include <QHash>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QList>
#include <QJsonObject>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPushButton>
#include <QTextDocument>
#include <QTextEdit>
#include <QTextOption>
#include <QVBoxLayout>
#include <QStringList>
#include <string>
#include <vector>

static constexpr qint64 MAX_REVIEW_REQUEST_BYTES = 64 * 1024;

static void usage(FILE* fp, const char* argv0) {
    fprintf(
        fp,
        "Usage: %s --review | --title <title> --text <text> "
        "--option <label> [--option <label> ...] | --input <default-text>\n",
        argv0
    );
    std::exit(fp == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

class FitText : public QTextEdit {
   public:
    explicit FitText(const QString& text, QWidget* parent = nullptr) : QTextEdit(text, parent) {
        setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    }

    bool hasHeightForWidth() const override {
        return true;
    }
    QSize minimumSizeHint() const override {
        return QSize(QTextEdit::minimumSizeHint().width(), 0);
    }
    int heightForWidth(int w) const override {
        const int inner = w - 2 * frameWidth();
        if (inner <= 0) return -1;
        auto* doc = const_cast<QTextDocument*>(document());
        doc->setTextWidth(qreal(inner));
        return qCeil(doc->size().height()) + 2 * frameWidth();
    }
};

static QByteArray readBoundedLine() {
    QByteArray input;
    char buffer[4096];
    while (std::fgets(buffer, int(sizeof(buffer)), stdin) != nullptr) {
        input.append(buffer);
        if (input.size() > MAX_REVIEW_REQUEST_BYTES) return {};
        if (input.endsWith('\n')) return input;
    }
    return {};
}

static int runReview() {
    const QByteArray input = readBoundedLine();
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(input, &error);
    if (input.isEmpty() || error.error != QJsonParseError::NoError || !document.isObject()) {
        return EXIT_FAILURE;
    }
    const QJsonObject request = document.object();
    if (request.value("version").toInt() != 1 || !request.value("summary").isString() ||
        !request.value("context").isArray() || !request.value("scopes").isArray() ||
        !request.value("fields").isArray()) {
        return EXIT_FAILURE;
    }

    QDialog dialog;
    dialog.setWindowTitle("agent-sandbox approval");
    dialog.setMinimumWidth(520);
    auto* layout = new QVBoxLayout(&dialog);

    const QJsonValue rawPresentation = request.value("presentation");
    if (!rawPresentation.isUndefined() &&
        (!rawPresentation.isObject() ||
         !rawPresentation.toObject().value("heading").isString() ||
         !rawPresentation.toObject().value("subject").isString())) {
        return EXIT_FAILURE;
    }
    const bool structured = !rawPresentation.isUndefined();
    const QJsonObject presentation = rawPresentation.toObject();
    if (structured) {
        auto* heading = new QLabel(presentation.value("heading").toString(), &dialog);
        heading->setTextFormat(Qt::PlainText);
        heading->setWordWrap(true);
        auto headingFont = heading->font();
        headingFont.setBold(true);
        headingFont.setPointSize(headingFont.pointSize() + 2);
        heading->setFont(headingFont);
        heading->setAccessibleName("Request heading");
        heading->setFocusPolicy(Qt::NoFocus);
        layout->addWidget(heading);

        auto* subject = new QLabel(presentation.value("subject").toString(), &dialog);
        subject->setTextFormat(Qt::PlainText);
        subject->setWordWrap(true);
        subject->setTextInteractionFlags(Qt::TextSelectableByMouse);
        subject->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        subject->setAccessibleName("Requested target");
        subject->setFocusPolicy(Qt::NoFocus);
        layout->addWidget(subject);
    } else {
        auto* summary = new QLabel(request.value("summary").toString(), &dialog);
        summary->setTextFormat(Qt::PlainText);
        summary->setWordWrap(true);
        summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
        summary->setAccessibleName("Request summary");
        summary->setFocusPolicy(Qt::NoFocus);
        layout->addWidget(summary);
    }

    const QJsonArray context = request.value("context").toArray();
    if (!context.isEmpty()) {
        if (structured) {
            auto* contextLayout = new QFormLayout();
            contextLayout->setContentsMargins(0, 4, 0, 0);
            contextLayout->setHorizontalSpacing(12);
            contextLayout->setVerticalSpacing(4);
            contextLayout->setLabelAlignment(Qt::AlignLeft | Qt::AlignTop);
            contextLayout->setFormAlignment(Qt::AlignLeft | Qt::AlignTop);
            contextLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
            for (const QJsonValue& raw : context) {
                const QJsonObject item = raw.toObject();
                if (!item.value("label").isString() || !item.value("value").isString()) {
                    return EXIT_FAILURE;
                }
                const QString label = item.value("label").toString();
                const QString displayValue = item.value("value").toString();
                auto* contextLabel = new QLabel(label, &dialog);
                contextLabel->setTextFormat(Qt::PlainText);
                contextLabel->setWordWrap(true);
                contextLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                contextLabel->setAccessibleName(label);
                contextLabel->setFocusPolicy(Qt::NoFocus);
                auto* contextValue = new QLabel(displayValue, &dialog);
                contextValue->setTextFormat(Qt::PlainText);
                contextValue->setWordWrap(true);
                contextValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
                contextValue->setToolTip(displayValue);
                contextValue->setAccessibleName(label);
                contextValue->setAccessibleDescription(displayValue);
                contextValue->setFocusPolicy(Qt::NoFocus);
                contextLayout->addRow(contextLabel, contextValue);
            }
            layout->addLayout(contextLayout);
        } else {
            auto* contextLayout = new QVBoxLayout();
            contextLayout->setSpacing(2);
            for (const QJsonValue& raw : context) {
                const QJsonObject item = raw.toObject();
                if (!item.value("label").isString() || !item.value("value").isString()) {
                    return EXIT_FAILURE;
                }
                const QString label = item.value("label").toString();
                const QString displayValue = item.value("value").toString();
                auto* contextLabel = new QLabel(label + ": " + displayValue, &dialog);
                contextLabel->setTextFormat(Qt::PlainText);
                contextLabel->setWordWrap(true);
                contextLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                contextLabel->setToolTip(displayValue);
                contextLabel->setAccessibleName(label);
                contextLabel->setAccessibleDescription(displayValue);
                contextLabel->setFocusPolicy(Qt::NoFocus);
                contextLayout->addWidget(contextLabel);
            }
            layout->addLayout(contextLayout);
        }
    }

    auto* scope = new QComboBox(&dialog);
    const QJsonArray scopes = request.value("scopes").toArray();
    for (const QJsonValue& raw : scopes) {
        const QJsonObject item = raw.toObject();
        if (!item.value("value").isString() || !item.value("label").isString()) {
            return EXIT_FAILURE;
        }
        scope->addItem(item.value("label").toString(), item.value("value").toString());
    }
    if (scope->count() == 0 || scope->itemData(0).toString() != "once") return EXIT_FAILURE;
    auto* scopeLayout = new QFormLayout();
    scopeLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    scopeLayout->addRow(structured ? "Allow for:" : "Scope:", scope);
    layout->addLayout(scopeLayout);

    QWidget* targets = nullptr;
    QFormLayout* targetLayout = nullptr;
    if (structured) {
        targets = new QWidget(&dialog);
        auto* targetSection = new QVBoxLayout(targets);
        targetSection->setContentsMargins(0, 6, 0, 0);
        targetSection->setSpacing(4);
        auto* targetHeading = new QLabel("Future request rule", targets);
        targetHeading->setTextFormat(Qt::PlainText);
        targetHeading->setAccessibleName("Future request rule");
        targetHeading->setFocusPolicy(Qt::NoFocus);
        auto targetHeadingFont = targetHeading->font();
        targetHeadingFont.setBold(true);
        targetHeading->setFont(targetHeadingFont);
        targetSection->addWidget(targetHeading);
        targetLayout = new QFormLayout();
        targetLayout->setContentsMargins(0, 0, 0, 0);
        targetLayout->setHorizontalSpacing(12);
        targetLayout->setVerticalSpacing(4);
        targetLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
        targetSection->addLayout(targetLayout);
    } else {
        auto* group = new QGroupBox("Rule for future requests", &dialog);
        targets = group;
        targetLayout = new QFormLayout(group);
        targetLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    }
    QHash<QString, QWidget*> controls;
    QList<QWidget*> fieldOrder;
    const QJsonArray fields = request.value("fields").toArray();
    for (const QJsonValue& raw : fields) {
        const QJsonObject field = raw.toObject();
        const QString id = field.value("id").toString();
        const QString label = field.value("label").toString();
        const QString kind = field.value("kind").toString();
        if (id.isEmpty() || label.isEmpty() || controls.contains(id)) return EXIT_FAILURE;
        QWidget* control = nullptr;
        if (kind == "text" && field.value("value").isString()) {
            control = new QLineEdit(field.value("value").toString(), targets);
        } else if (
            kind == "choice" && field.value("value").isString() && field.value("options").isArray()
        ) {
            auto* combo = new QComboBox(targets);
            for (const QJsonValue& rawOption : field.value("options").toArray()) {
                const QJsonObject option = rawOption.toObject();
                if (!option.value("value").isString() || !option.value("label").isString()) {
                    return EXIT_FAILURE;
                }
                combo->addItem(option.value("label").toString(), option.value("value").toString());
            }
            const int selected = combo->findData(field.value("value").toString());
            if (combo->count() == 0 || selected < 0) return EXIT_FAILURE;
            combo->setCurrentIndex(selected);
            control = combo;
        } else {
            return EXIT_FAILURE;
        }
        control->setAccessibleName(label);
        controls.insert(id, control);
        fieldOrder.append(control);
        targetLayout->addRow(label + ":", control);
    }
    layout->addWidget(targets);
    auto* errorLabel = new QLabel(&dialog);
    errorLabel->setWordWrap(true);
    errorLabel->setStyleSheet("QLabel { color: red; }");
    errorLabel->hide();
    layout->addWidget(errorLabel);

    auto* buttons = new QHBoxLayout();
    auto* deny = new QPushButton("Deny", &dialog);
    auto* allow = new QPushButton("Allow once", &dialog);
    deny->setDefault(true);
    deny->setAutoDefault(true);
    deny->setFocus();
    buttons->addStretch(1);
    buttons->addWidget(deny);
    buttons->addWidget(allow);
    layout->addLayout(buttons);

    QWidget* lastTab = scope;
    for (QWidget* control : fieldOrder) {
        QWidget::setTabOrder(lastTab, control);
        lastTab = control;
    }
    QWidget::setTabOrder(lastTab, deny);
    QWidget::setTabOrder(deny, allow);

    QString action = "deny";
    const auto buildResult = [&]() {
        QJsonObject values;
        for (auto it = controls.constBegin(); it != controls.constEnd(); ++it) {
            if (auto* edit = qobject_cast<QLineEdit*>(it.value())) {
                values.insert(it.key(), edit->text());
            } else if (auto* combo = qobject_cast<QComboBox*>(it.value())) {
                values.insert(it.key(), combo->currentData().toString());
            }
        }
        const QJsonObject result{
            {"action", action}, {"scope", scope->currentData().toString()}, {"values", values}
        };
        return QJsonDocument(result).toJson(QJsonDocument::Compact);
    };
    const auto writeResult = [&]() {
        const QByteArray output = buildResult();
        if (std::fwrite(output.constData(), 1, size_t(output.size()), stdout) !=
                size_t(output.size()) ||
            std::fputc('\n', stdout) == EOF) {
            return false;
        }
        std::fflush(stdout);
        return true;
    };
    const auto readValidation = [&]() {
        char line[4096];
        if (std::fgets(line, int(sizeof(line)), stdin) == nullptr) return -1;
        QJsonParseError parseError;
        const auto response =
            QJsonDocument::fromJson(QByteArray(line).trimmed(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !response.isObject()) return -1;
        const QJsonObject object = response.object();
        if (object.value("valid").toBool()) return 1;
        errorLabel->setText(object.value("error").toString("Invalid input."));
        errorLabel->show();
        return 0;
    };
    const auto submit = [&]() {
        if (!writeResult()) {
            dialog.done(QDialog::Rejected);
            return;
        }
        const int validation = readValidation();
        if (validation > 0) {
            dialog.done(QDialog::Accepted);
        } else if (validation < 0) {
            dialog.done(QDialog::Rejected);
        }
    };

    QObject::connect(deny, &QPushButton::clicked, &dialog, [&]() {
        action = "deny";
        submit();
    });
    QObject::connect(allow, &QPushButton::clicked, &dialog, [&]() {
        action = "allow";
        submit();
    });
    const auto updateScope = [&]() {
        const QString scopeValue = scope->currentData().toString();
        const bool once = scopeValue == "once";
        targets->setEnabled(!once);
        if (once) {
            allow->setText("Allow once");
        } else if (scopeValue == "global") {
            allow->setText("Allow globally");
        } else {
            allow->setText("Allow for " + scope->currentText().toLower());
        }
    };
    QObject::connect(scope, qOverload<int>(&QComboBox::currentIndexChanged), &dialog, [&](int) {
        updateScope();
    });
    updateScope();

    return dialog.exec() == QDialog::Accepted ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int runLegacy(
    const std::string& title,
    const std::string& text,
    const std::vector<std::string>& options,
    const std::string& inputDefault
) {
    QDialog dialog;
    dialog.setWindowTitle(QString::fromStdString(title));
    dialog.setMinimumWidth(400);
    auto* mainLayout = new QVBoxLayout(&dialog);
    auto* prompt = new FitText(QString::fromStdString(text), &dialog);
    prompt->setReadOnly(true);
    prompt->setFrameShape(QFrame::NoFrame);
    prompt->setFocusPolicy(Qt::NoFocus);
    QPalette promptPalette = prompt->palette();
    promptPalette.setColor(QPalette::Base, dialog.palette().color(QPalette::Window));
    prompt->setPalette(promptPalette);
    prompt->setFont(dialog.font());
    prompt->setLineWrapMode(QTextEdit::WidgetWidth);
    prompt->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    mainLayout->addWidget(prompt);

    QLineEdit* edit = nullptr;
    auto* btnLayout = new QVBoxLayout();
    mainLayout->addLayout(btnLayout);
    std::string selected;
    if (!options.empty()) {
        for (const auto& opt : options) {
            auto* btn = new QPushButton(QString::fromStdString(opt), &dialog);
            btn->setStyleSheet("text-align: left; padding: 6px 12px;");
            btn->setMinimumHeight(btn->fontMetrics().height() + 12 + 8);
            btnLayout->addWidget(btn);
            QObject::connect(btn, &QPushButton::clicked, [&dialog, &selected, opt]() {
                selected = opt;
                dialog.accept();
            });
        }
    } else {
        edit = new QLineEdit(QString::fromStdString(inputDefault), &dialog);
        edit->selectAll();
        edit->setFocus();
        auto* btnRow = new QHBoxLayout();
        btnRow->addStretch(1);
        auto* okBtn = new QPushButton("OK", &dialog);
        okBtn->setDefault(true);
        auto* cancelBtn = new QPushButton("Cancel", &dialog);
        btnRow->addWidget(okBtn);
        btnRow->addWidget(cancelBtn);
        QObject::connect(okBtn, &QPushButton::clicked, &dialog, &QDialog::accept);
        QObject::connect(edit, &QLineEdit::returnPressed, &dialog, &QDialog::accept);
        QObject::connect(cancelBtn, &QPushButton::clicked, &dialog, &QDialog::reject);
        mainLayout->addWidget(edit);
        mainLayout->addLayout(btnRow);
    }

    const int dlgW = qMax(dialog.sizeHint().width(), dialog.minimumWidth());
    const int contentW =
        dlgW - mainLayout->contentsMargins().left() - mainLayout->contentsMargins().right();
    QTextDocument measureDoc(QString::fromStdString(text));
    measureDoc.setDefaultFont(prompt->font());
    QTextOption to = measureDoc.defaultTextOption();
    to.setWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere);
    measureDoc.setDefaultTextOption(to);
    measureDoc.setTextWidth(qreal(contentW));
    prompt->setMinimumHeight(qCeil(measureDoc.size().height()));
    if (btnLayout->itemAt(0) != nullptr) {
        if (auto* firstBtn = btnLayout->itemAt(0)->widget()) firstBtn->setFocus();
    }
    if (dialog.exec() != QDialog::Accepted) return EXIT_FAILURE;
    std::string result;
    if (!options.empty())
        result = selected;
    else if (edit != nullptr)
        result = edit->text().toStdString();
    if (result.empty()) return EXIT_FAILURE;
    std::printf("%s\n", result.c_str());
    std::fflush(stdout);
    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    std::string title;
    std::string text;
    std::vector<std::string> options;
    std::string inputDefault;
    bool review = false;
    enum { OPT_TITLE = 256, OPT_TEXT, OPT_OPTION, OPT_INPUT, OPT_REVIEW };
    static struct option long_opts[] = {
        {"title", required_argument, nullptr, OPT_TITLE},
        {"text", required_argument, nullptr, OPT_TEXT},
        {"option", required_argument, nullptr, OPT_OPTION},
        {"input", required_argument, nullptr, OPT_INPUT},
        {"review", no_argument, nullptr, OPT_REVIEW},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    int ch;
    while ((ch = getopt_long(argc, argv, "h", long_opts, nullptr)) != -1) {
        switch (ch) {
            case OPT_TITLE:
                title = optarg;
                break;
            case OPT_TEXT:
                text = optarg;
                break;
            case OPT_OPTION:
                options.emplace_back(optarg);
                break;
            case OPT_INPUT:
                inputDefault = optarg;
                break;
            case OPT_REVIEW:
                review = true;
                break;
            case 'h':
                usage(stdout, argv[0]);
                break;
            default:
                usage(stderr, argv[0]);
        }
    }
    const bool haveOptions = !options.empty();
    const bool haveInput = !inputDefault.empty();
    if (review) {
        if (!title.empty() || !text.empty() || haveOptions || haveInput) usage(stderr, argv[0]);
    } else if (title.empty() || text.empty() || (haveOptions == haveInput)) {
        usage(stderr, argv[0]);
    }

    QApplication app(argc, argv);
    QApplication::setApplicationName("agent-sandbox");
    return review ? runReview() : runLegacy(title, text, options, inputDefault);
}
