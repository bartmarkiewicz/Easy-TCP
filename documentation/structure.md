## Program Structure

The app will be a JFrame, see 'easytcp.view.EasyTCP'. 


#### Layout
The program JFrame will consist of a grid layout with 2 rows,
the first row will contain a JPanel with a grid layout of a single row with two columns.
This is to have a GridLayout with different sized items. This JPanel will contain
the easytcp.view.ArrowDiagram which will be a class extending a JPanel, and the options panel which
will be another class extending JPanel.

The second row of the overall JFrame will consist of a JScrollPane which will
contain the text based easytcp.view of the captured packets.




____
[Panel1][Panel2] \
[panel 3       ]

____