from pyope.ope import OPE, ValueRange

# class OREComparable():
#    def __init__(self, number):
#       self.number = number
   
#    def __int__(self):
#        return self.number

#    def __index__(self):
#        return self.number

#    def __lt__(self, other):
#       return self.number < other
           
#    def __gt__(self, other):
#       return self.number > other

#    # def export(self):
#    #    return 

class OREcipher():
   def __init__(self,
                key=OPE.generate_key(256),
                parameters={
                              "ORE_IN_MIN":0,
                              "ORE_IN_MAX": (2**64)-1,
                              "ORE_OUT_MIN":0,
                              "ORE_OUT_MAX": (2**128)-1 
                           }):
      self.key = key

      if type(parameters) != dict:
         raise TypeError("'parameters' must be dict")
      if "ORE_IN_MIN" not in parameters:
         raise ValueError("'ORE_IN_MIN' required key in 'parameters'")
      if "ORE_IN_MAX" not in parameters:
         raise ValueError("'ORE_IN_MAX' required key in 'parameters'")
      if "ORE_OUT_MIN" not in parameters:
         raise ValueError("'ORE_OUT_MIN' required key in 'parameters'")
      if "ORE_OUT_MAX" not in parameters:
         raise ValueError("'ORE_OUT_MAX' required key in 'parameters'")

      self.parameters = parameters
      
      self.ORE_IN_MIN = parameters["ORE_IN_MIN"]
      self.ORE_IN_MAX = parameters["ORE_IN_MAX"]
      self.ORE_OUT_MIN = parameters["ORE_OUT_MIN"]
      self.ORE_OUT_MAX = parameters["ORE_OUT_MAX"]

      self.cipher = OPE(self.key, in_range=ValueRange(self.ORE_IN_MIN, self.ORE_IN_MAX),
                                    out_range=ValueRange(self.ORE_OUT_MIN, self.ORE_OUT_MAX))
      
   def encrypt(self, number):
      return self.cipher.encrypt(number)

   def decrypt(self, number):
      return self.cipher.decrypt(number)
   
   def export_key(self):
      return self.key
   def export_params(self):
      return self.parameters



