"""Single-output exact-synthesis encoders: AIG (certlab.encoders.aig), XAG (certlab.encoders.xag)
and MIG (certlab.encoders.mig).
Multi-output encoders (phase 2): certlab.encoders.multi_aig and certlab.encoders.multi_mig.

Truth-table convention shared by all of them: tt is an integer of 2^n bits, bit t = f(row t), and
input x_j (1-based) is bit j-1 of the row index t (x_1 is the least significant bit).
"""
