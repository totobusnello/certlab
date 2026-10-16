"""Single-output exact-synthesis encoders: AIG (certlab.encoders.aig), XAG (certlab.encoders.xag)
and MIG (certlab.encoders.mig).

Truth-table convention shared by all three: tt is an integer of 2^n bits, bit t = f(row t), and
input x_j (1-based) is bit j-1 of the row index t (x_1 is the least significant bit).
"""
