package easytcp.service;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/*Wrapper around a DocumentListener to remove some boilerplate code
 */
@FunctionalInterface
public interface DocumentUpdateListener extends DocumentListener {
  void update(DocumentEvent e);

  @Override
  default void insertUpdate(DocumentEvent e) {
    update(e);
  }
  @Override
  default void removeUpdate(DocumentEvent e) {
    update(e);
  }
  @Override
  default void changedUpdate(DocumentEvent e) {
    update(e);
  }
}