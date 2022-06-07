#Actual controller producing outputs from inputs

class Controller:    
    def __init__(self):
        self.curtainState = [0,0,0] #R2, R3, R4
        self.reqTempEco = 23
        
    def __isAcOn(self, acState):
        return acState == 3 or acState == 1
    
    def __getReqTemp(self, acState, reqTempComf):
        if acState == 1:
            return reqTempComf
        else:
            return self.reqTempEco
    
    def __getUpperThreshold(self, temp):
        return temp + 1.5
    
    def __getLowerThreshold(self, temp):
        return temp - 1.5
    
    def __getRequiredRoomCurState(self, currentCurState, acState, reqTempComf, curTemp):
        if currentCurState == 0:
            #Curtains are open
            if curTemp > self.__getUpperThreshold(self.__getReqTemp(acState, reqTempComf)):
                #Its time to close curtains
                return 1
            else:
                return currentCurState
        else:
            #Curtains are closed
            if curTemp < self.__getLowerThreshold(self.__getReqTemp(acState, reqTempComf)):
                #Its time to open curtains
                return 0
            else:
                return currentCurState
    
    def update(self, input_dict):
        self.curtainState[0] = self.__getRequiredRoomCurState(self.curtainState[0],
                                                              input_dict['R2-AcMod'],
                                                              input_dict['R2-AcTempTgt'],
                                                              input_dict['ST2T'])
        self.curtainState[1] = self.__getRequiredRoomCurState(self.curtainState[1],
                                                              input_dict['R3-AcMod'],
                                                              input_dict['R3-AcTempTgt'],
                                                              input_dict['ST3T'])
        self.curtainState[2] = self.__getRequiredRoomCurState(self.curtainState[2],
                                                              input_dict['R4-AcMod'],
                                                              input_dict['R4-AcTempTgt'],
                                                              input_dict['ST4T'])
        
        return {'Z2.1ReqPosAutoSet': self.curtainState[0], 'Z2.2ReqPosAutoSet': self.curtainState[0],
                'Z3.1ReqPosAutoSet': self.curtainState[1], 'Z3.2ReqPosAutoSet': self.curtainState[1],
                'Z4ReqPosAutoSet': self.curtainState[2] }