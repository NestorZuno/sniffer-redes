from PyQt6.QtWidgets import QWidget, QTreeWidget, QTreeWidgetItem, QVBoxLayout

class PacketDetails(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Campo", "Valor"])

        layout.addWidget(self.tree)

    def display(self, layers: list):
        self.tree.clear()

        for layer in layers:
            layer_item = QTreeWidgetItem([layer["layer"]])
            self.tree.addTopLevelItem(layer_item)

            for field, value in layer["fields"].items():
                QTreeWidgetItem(layer_item, [field, str(value)])

        self.tree.expandAll()
