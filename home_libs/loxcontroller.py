#Actual controller producing outputs from inputs

class Controller:
    def __init__(self):
        pass
    
    def update(self, input_dict):
        return {'Z2.1ReqPosAuto': input_dict['Z2.1Pos'], 'Z2.2ReqPosAuto': input_dict['Z2.2Pos'],
                'Z3.1ReqPosAuto': input_dict['Z3.1Pos'], 'Z3.2ReqPosAuto': input_dict['Z3.2Pos'],
                'Z4ReqPosAuto': input_dict['Z4Pos'] }