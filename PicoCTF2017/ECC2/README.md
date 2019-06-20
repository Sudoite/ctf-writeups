# ECC2

This is a level 4, 200-point cryptography problem from PicoCTF2017.

[Note: As this is a PDF of a Markdown document, some text may be cut off in the code sections. Please direct your browser to https://github.com/Sudoite/ctf-writeups/tree/master/CSAW2018/turtles/turtles.md for the original write-up.]

Here's the problem statement:

    Elliptic Curve: y^2 = x^3 + A*x + B mod M
    M = 93556643250795678718734474880013829509320385402690660619699653921022012489089
    A = 66001598144012865876674115570268990806314506711104521036747533612798434904785
    B = *You can figure this out with the point below :)*

    P = (56027910981442853390816693056740903416379421186644480759538594137486160388926, 65533262933617146434438829354623658858649726233622196512439589744498050226926)
    n = *SECRET*
    n*P = (23587034938374768786301222539991586253242655515915989431307599794801199763403, 58594847963665471409425852843336835079537055974819057000500246625851308476858)

    n < 400000000000000000000000000000

    Find n.

Knowing nothing about elliptic curves, I started by reading Chapter 6 of Neal Koblitz's book, *A Course in Number Theory and Cryptography: Second Edition*.

Next, it's straightforward enough to calculate B given P = (x1, y1), M, and A. We then have the discrete log problem for elliptic curves (ECDLP), with small n.

B is just

    (y^2 - x^3 - A^x) mod M,

or 25255205054024371783896605039267101837972419055969636393425590261926131199030. A [primality test](https://www.alpertron.com.ar/ECM.HTM) shows that M is prime.

### Blind alley: Pollard's Lambda algorithm

I considered constructing an elliptic curve in `SageMath` and usinig Pollard's lambda algorithm to find n, given that it exists within a bounded interval. Pollard's lambda will run in roughly `O(sqrt(2^84))` time in this case, so that is probably too long. Indeed, Pollard's lambda had still not finished after an hour, so I considered that I had to somehow further simplify the problem.

Next, [this post](https://crypto.stackexchange.com/questions/45325/pollards-lambda-algorithm-ecdlp-with-pohlig-hellman) suggests that I might try factoring M-1 first.

Factoring M-1 gives the following:
    {mpz(13119233): 1, 2: 7, mpz(4651): 1, mpz(8700401374293253191538844922014903691311L): 1, mpz(5917231): 1, mpz(232676254765026257): 1}

so the largest factor is 8700401374293253191538844922014903691311, on the order of 2^92. That's a lot better than 2^177! And [this paper](https://koclab.cs.ucsb.edu/teaching/ecc/project/2015Projects/Sommerseth+Hoeiland.pdf) suggests that we can solve the Elliptic Curve Discrete Log Problem (ECDLP) in acceptable time when the largest factor is less than 2^160. But in practice, I'm not convinced that the Pohlig-Hellman algorithm is going to work in reasonable time, given the size of that largest factor.


### After a small hint from a forum post

Stuck, I took a look at the hint for the problem, which just confirmed that I was doing the right thing by using `SageMath`. Next I read the first few lines of a Piazza forum post (a complete write-up in this case), and the first thing I realized is that I factored the wrong integer. Whereas the order of a finite field would generally be `M-1` as `M` is prime, for an elliptic curve the order is the number of points on the curve, `N`, is almost never `M-1`. We can calculate `N` in `O(log^8 M)` operations with an algorithm by Rene Schoof (Koblitz 1994: 179). There also appear to be better algorithms for it, as implemented with the `cardinality()` method associated with an `EllipticCurve` object in `SageMath`.

Factoring the actual number of points on the curve, I get:

    2^2 * 3 * 5 * 7 * 137 * 593 * 24337 * 25589 * 3637793 * 5733569 * 106831998530025000830453 * 1975901744727669147699767

The largest factor is still quite large, around 2^84. It does not make sense that the Pohlig-Hellman algorithm would help here! I read a few lines in the forum post, and they tried debugging the Pohlig-Hellman algorithm by reimplementing it -- so I figured that I would give it a shot. I downloaded the source code for `SageMath` to get the algorithm itself -- an important thing to do for clarity because while the writers of the forum post believed that the implementation of Pohlig-Hellman in `SageMath`'s `discrete_log` function calls Pollard's Rho, in fact it calls the Baby Step Giant Step algorithm. In any case, both `bsgs` and Pollard's Rho have the same running time, the square root of the largest prime factor of the number of points on the elliptic curve. So that oversight doesn't make a difference here.

Next, I went ahead and re-implemented the SageMath code for the Pohlig-Hellman algorithm. Here's the `SageMath` source code, for reference:

    def discrete_log(a, base, ord=None, bounds=None, operation='*', identity=None, inverse=None, op=None):
    r"""
    Totally generic discrete log function.

    INPUT:

    - ``a``    - group element
    - ``base`` - group element (the base)
    - ``ord``  - integer (multiple of order of base, or ``None``)
    - ``bounds`` - a priori bounds on the log
    - ``operation`` - string: '*', '+', 'other'
    - ``identity`` - the group's identity
    - ``inverse()`` - function of 1 argument ``x`` returning inverse of ``x``
    - ``op()`` - function of 2 arguments ``x``, ``y`` returning ``x*y`` in group

    ``a`` and ``base`` must be elements of some group with identity
    given by identity, inverse of ``x`` by ``inverse(x)``, and group
    operation on ``x``, ``y`` by ``op(x,y)``.

    If operation is '*' or '+' then the other
    arguments are provided automatically; otherwise they must be
    provided by the caller.

    OUTPUT: Returns an integer `n` such that `b^n = a` (or `nb = a`),
    assuming that ``ord`` is a multiple of the order of the base `b`.
    If ``ord`` is not specified, an attempt is made to compute it.

    If no such `n` exists, this function raises a ValueError exception.

    .. warning::

     If ``x`` has a log method, it is likely to be vastly faster
     than using this function.  E.g., if ``x`` is an integer modulo
     `n`, use its log method instead!

    ALGORITHM: Pohlig-Hellman and Baby step giant step.

    EXAMPLES::

      sage: b = Mod(2,37);  a = b^20
      sage: discrete_log(a, b)
      20
      sage: b = Mod(2,997);  a = b^20
      sage: discrete_log(a, b)
      20

      sage: K = GF(3^6,'b')
      sage: b = K.gen()
      sage: a = b^210
      sage: discrete_log(a, b, K.order()-1)
      210

      sage: b = Mod(1,37);  x = Mod(2,37)
      sage: discrete_log(x, b)
      Traceback (most recent call last):
      ...
      ValueError: No discrete log of 2 found to base 1
      sage: b = Mod(1,997);  x = Mod(2,997)
      sage: discrete_log(x, b)
      Traceback (most recent call last):
      ...
      ValueError: No discrete log of 2 found to base 1

    See :trac:`2356`::

      sage: F.<w> = GF(121)
      sage: v = w^120
      sage: v.log(w)
      0

      sage: K.<z>=CyclotomicField(230)
      sage: w=z^50
      sage: discrete_log(w,z)
      50

    An example where the order is infinite: note that we must give
    an upper bound here::

      sage: K.<a> = QuadraticField(23)
      sage: eps = 5*a-24        # a fundamental unit
      sage: eps.multiplicative_order()
      +Infinity
      sage: eta = eps^100
      sage: discrete_log(eta,eps,bounds=(0,1000))
      100

    In this case we cannot detect negative powers::

      sage: eta = eps^(-3)
      sage: discrete_log(eta,eps,bounds=(0,100))
      Traceback (most recent call last):
      ...
      ValueError: No discrete log of -11515*a - 55224 found to base 5*a - 24

    But we can invert the base (and negate the result) instead::

      sage: - discrete_log(eta^-1,eps,bounds=(0,100))
      -3

    An additive example: elliptic curve DLOG::

      sage: F=GF(37^2,'a')
      sage: E=EllipticCurve(F,[1,1])
      sage: F.<a>=GF(37^2,'a')
      sage: E=EllipticCurve(F,[1,1])
      sage: P=E(25*a + 16 , 15*a + 7 )
      sage: P.order()
      672
      sage: Q=39*P; Q
      (36*a + 32 : 5*a + 12 : 1)
      sage: discrete_log(Q,P,P.order(),operation='+')
      39

    An example of big smooth group::

      sage: F.<a>=GF(2^63)
      sage: g=F.gen()
      sage: u=g**123456789
      sage: discrete_log(u,g)
      123456789

    AUTHORS:

    - William Stein and David Joyner (2005-01-05)
    - John Cremona (2008-02-29) rewrite using ``dict()`` and make generic

    """
    if ord is None:
      if operation in multiplication_names:
          try:
              ord = base.multiplicative_order()
          except Exception:
              ord = base.order()
      elif operation in addition_names:
          try:
              ord = base.additive_order()
          except Exception:
              ord = base.order()
      else:
          try:
              ord = base.order()
          except Exception:
              raise ValueError("ord must be specified")
    try:
      from sage.rings.infinity import Infinity
      if ord==+Infinity:
          return bsgs(base,a,bounds, operation=operation)
      if ord==1 and a!=base:
          raise ValueError
      f=ord.factor()
      l=[0]*len(f)
      for i,(pi,ri) in enumerate(f):
          for j in range(ri):
              if operation in multiplication_names:
                  c=bsgs(base**(ord//pi),(a/base**l[i])**(ord//pi**(j+1)),(0,pi),operation=operation)
                  l[i] += c*(pi**j)
              elif operation in addition_names:
                  c=bsgs(base*(ord//pi),(a-base*l[i])*(ord//pi**(j+1)),(0,pi),operation=operation)
                  l[i] += c*(pi**j)
      from sage.arith.all import CRT_list
      return  CRT_list(l,[pi**ri for pi,ri in f])
    except ValueError:
      raise ValueError("No discrete log of %s found to base %s"%(a,base))

Here's my ugly SAGE code:

    A = 66001598144012865876674115570268990806314506711104521036747533612798434904785
    B = 25255205054024371783896605039267101837972419055969636393425590261926131199030
    F = GF(93556643250795678718734474880013829509320385402690660619699653921022012489089)
    E = EllipticCurve(F, [A, B])
    Px = 56027910981442853390816693056740903416379421186644480759538594137486160388926
    P = E.lift_x(Px, all=True)[1]
    nPx = 23587034938374768786301222539991586253242655515915989431307599794801199763403
    Q = E.lift_x(nPx, all=True)[1]
    print(Q)

    # Replicating:
    #n = discrete_log(a=Q, base=P, ord = P.order(), bounds = (0, 400000000000000000000000000000), operation='+')

    a = Q
    base = P
    bounds = (0, 400000000000000000000000000000)
    operation='+'
    ord = base.order()
    f = ord.factor()
    l = [0]*len(f)
    for i,(pi,ri) in enumerate(f):
    for j in range(ri):
        print("i = " + str(i))
        print("pi = " + str(pi))
        print("ri = " + str(ri))
        print("bsgs: a = " + str(base*(ord//pi)))
        print("ord//pi = " + str(ord//pi))
        print("base = " + str(base))
        print("bsgs: b = " + str((a-base*l[i])*(ord//pi**(j+1))))
        if pi < 2**70:
            c=bsgs(base*(ord//pi),(a-base*l[i])*(ord//pi**(j+1)),(0,pi),operation=operation)
        else:
            print("running discrete_log_lambda")
            print("l so far: " + str(l[0:i]))
            print("f so far: " + str(f[0:i]))
            print("CRT output so far: " + str(CRT_list(l[0:i],[pi**ri for pi, ri in f[0:i]])))
            print("CRT_list remainders: " + str(l[0:i]))
            print("CRT_list modules: " + str([pi**ri for pi, ri in f[0:i]]))
            # CRT_list(l,[pi**ri for pi,ri in f])
            c=discrete_log_lambda((a-base*l[i])*(ord//pi**(j+1)),base*(ord//pi),bounds=bounds,operation=operation)
        print("c = " + str(c))
        l[i] += c*(pi**j)
        print("l = " + str(l))
        print("\n")

    # CRT output so far: 249838002898687975937532407250
    # N is less than:    400000000000000000000000000000
    # It chokes on bsgs for 106831998530025000830453

Running that code produces, among other things:

    running discrete_log_lambda
    l so far: [2, 0, 0, 0, 130, 530, 5173, 24401, 1403911, 2087121]
    f so far: [(2, 2), (3, 1), (5, 1), (7, 1), (137, 1), (593, 1), (24337, 1), (25589, 1), (3637793, 1), (5733569, 1)]
    CRT output so far: 249838002898687975937532407250
    CRT_list remainders: [2, 0, 0, 0, 130, 530, 5173, 24401, 1403911, 2087121]
    CRT_list modules: [4, 3, 5, 7, 137, 593, 24337, 25589, 3637793, 5733569]

So, right before attempting to run `bsgs` on the large prime factor 106831998530025000830453, the eventual input for the Chinese Remainder Theorem is already a large number, 249838002898687975937532407250, which is already more than half the upper bound on `n`, 400000000000000000000000000000. That seems to imply to me that I can probably infer something about the actual solution given the information I already have at this step in the problem. But what would that be? I worked through a few examples of applications of the Chinese Remainder Theorem and also read the source code in `SageMath`. Here it is:

    def crt(a,b,m=None,n=None):
        r"""
        Returns a solution to a Chinese Remainder Theorem problem.

        INPUT:

        - ``a``, ``b`` - two residues (elements of some ring for which
          extended gcd is available), or two lists, one of residues and
          one of moduli.

        - ``m``, ``n`` - (default: ``None``) two moduli, or ``None``.

        OUTPUT:

        If ``m``, ``n`` are not ``None``, returns a solution `x` to the
        simultaneous congruences `x\equiv a \bmod m` and `x\equiv b \bmod
        n`, if one exists. By the Chinese Remainder Theorem, a solution to the
        simultaneous congruences exists if and only if
        `a\equiv b\pmod{\gcd(m,n)}`. The solution `x` is only well-defined modulo
        `\text{lcm}(m,n)`.

        If ``a`` and ``b`` are lists, returns a simultaneous solution to
        the congruences `x\equiv a_i\pmod{b_i}`, if one exists.

        .. SEEALSO::

            - :func:`CRT_list`

        EXAMPLES:

        Using ``crt`` by giving it pairs of residues and moduli::

            sage: crt(2, 1, 3, 5)
            11
            sage: crt(13, 20, 100, 301)
            28013
            sage: crt([2, 1], [3, 5])
            11
            sage: crt([13, 20], [100, 301])
            28013

        You can also use upper case::

            sage: c = CRT(2,3, 3, 5); c
            8
            sage: c % 3 == 2
            True
            sage: c % 5 == 3
            True

        Note that this also works for polynomial rings::

            sage: K.<a> = NumberField(x^3 - 7)
            sage: R.<y> = K[]
            sage: f = y^2 + 3
            sage: g = y^3 - 5
            sage: CRT(1,3,f,g)
            -3/26*y^4 + 5/26*y^3 + 15/26*y + 53/26
            sage: CRT(1,a,f,g)
            (-3/52*a + 3/52)*y^4 + (5/52*a - 5/52)*y^3 + (15/52*a - 15/52)*y + 27/52*a + 25/52

        You can also do this for any number of moduli::

            sage: K.<a> = NumberField(x^3 - 7)
            sage: R.<x> = K[]
            sage: CRT([], [])
            0
            sage: CRT([a], [x])
            a
            sage: f = x^2 + 3
            sage: g = x^3 - 5
            sage: h = x^5 + x^2 - 9
            sage: k = CRT([1, a, 3], [f, g, h]); k
            (127/26988*a - 5807/386828)*x^9 + (45/8996*a - 33677/1160484)*x^8 + (2/173*a - 6/173)*x^7 + (133/6747*a - 5373/96707)*x^6 + (-6/2249*a + 18584/290121)*x^5 + (-277/8996*a + 38847/386828)*x^4 + (-135/4498*a + 42673/193414)*x^3 + (-1005/8996*a + 470245/1160484)*x^2 + (-1215/8996*a + 141165/386828)*x + 621/8996*a + 836445/386828
            sage: k.mod(f)
            1
            sage: k.mod(g)
            a
            sage: k.mod(h)
            3

        If the moduli are not coprime, a solution may not exist::

            sage: crt(4,8,8,12)
            20
            sage: crt(4,6,8,12)
            Traceback (most recent call last):
            ...
            ValueError: No solution to crt problem since gcd(8,12) does not divide 4-6

            sage: x = polygen(QQ)
            sage: crt(2,3,x-1,x+1)
            -1/2*x + 5/2
            sage: crt(2,x,x^2-1,x^2+1)
            -1/2*x^3 + x^2 + 1/2*x + 1
            sage: crt(2,x,x^2-1,x^3-1)
            Traceback (most recent call last):
            ...
            ValueError: No solution to crt problem since gcd(x^2 - 1,x^3 - 1) does not divide 2-x

            sage: crt(int(2), int(3), int(7), int(11))
            58
        """
        if isinstance(a, list):
            return CRT_list(a, b)
        if isinstance(a, integer_types):
            a = Integer(a) # otherwise we get an error at (b-a).quo_rem(g)
        g, alpha, beta = XGCD(m, n)  
        q, r = (b - a).quo_rem(g)
        if r != 0:
            raise ValueError("No solution to crt problem since gcd(%s,%s) does not divide %s-%s" % (m, n, a, b))
        from sage.arith.functions import lcm
        return (a + q*alpha*m) % lcm(m, n)

    CRT = crt

    def CRT_list(v, moduli):
        r""" Given a list ``v`` of elements and a list of corresponding
        ``moduli``, find a single element that reduces to each element of
        ``v`` modulo the corresponding moduli.

        .. SEEALSO::

            - :func:`crt`

        EXAMPLES::

            sage: CRT_list([2,3,2], [3,5,7])
            23
            sage: x = polygen(QQ)
            sage: c = CRT_list([3], [x]); c
            3
            sage: c.parent()
            Univariate Polynomial Ring in x over Rational Field

        It also works if the moduli are not coprime::

            sage: CRT_list([32,2,2],[60,90,150])
            452

        But with non coprime moduli there is not always a solution::

            sage: CRT_list([32,2,1],[60,90,150])
            Traceback (most recent call last):
            ...
            ValueError: No solution to crt problem since gcd(180,150) does not divide 92-1

        The arguments must be lists::

            sage: CRT_list([1,2,3],"not a list")
            Traceback (most recent call last):
            ...
            ValueError: Arguments to CRT_list should be lists
            sage: CRT_list("not a list",[2,3])
            Traceback (most recent call last):
            ...
            ValueError: Arguments to CRT_list should be lists

        The list of moduli must have the same length as the list of elements::

            sage: CRT_list([1,2,3],[2,3,5])
            23
            sage: CRT_list([1,2,3],[2,3])
            Traceback (most recent call last):
            ...
            ValueError: Arguments to CRT_list should be lists of the same length
            sage: CRT_list([1,2,3],[2,3,5,7])
            Traceback (most recent call last):
            ...
            ValueError: Arguments to CRT_list should be lists of the same length

        TESTS::

            sage: CRT([32r,2r,2r],[60r,90r,150r])
            452

        """
        if not isinstance(v,list) or not isinstance(moduli,list):
            raise ValueError("Arguments to CRT_list should be lists")
        if len(v) != len(moduli):
            raise ValueError("Arguments to CRT_list should be lists of the same length")
        if len(v) == 0:
            return ZZ(0)
        if len(v) == 1:
            return moduli[0].parent()(v[0])
        x = v[0]
        m = moduli[0]
        from sage.arith.functions import lcm
        for i in range(1, len(v)):
            x = CRT(x,v[i],m,moduli[i])
            m = lcm(m,moduli[i])
        return x%m

Note the final line in `discrete_log`:

    return  CRT_list(l,[pi**ri for pi,ri in f])

The Chinese Remainder Theorem gets called, passing in the solutions to each individual discrete log problem calculated in the Pohlig-Hellman algorithm. I do not know the solutions for the last two primes, but I know the solutions for the first few:

       CRT_list remainders: [2, 0, 0, 0, 130, 530, 5173, 24401, 1403911, 2087121]
       CRT_list modules: [4, 3, 5, 7, 137, 593, 24337, 25589, 3637793, 5733569]

If I pass those parameters in to `CRT_list`, I get back 249838002898687975937532407250 as previously mentioned. But notice the parameter `m` at the end of the `CRT_list()` function, which is calculated using `m = lcm(m,moduli[i])`. Then in the next step of the Chinese Remainder Theorem (the `crt()` function), the return value is `(a + q*alpha*m) % lcm(m, n)`. (The two parameters `m` are the same in these two functions.) What that means for the current problem is that we can calculate the value of `m` that would be passed into the next iteration of `crt`, assuming that the Pohlig-Hellman algorithm were to have solved the ECDLP for the large prime factor 106831998530025000830453. Here's some quick `SageMath` code to do it:

    sage: mi = [4, 3, 5, 7, 137, 593, 24337, 25589, 3637793, 5733569]
    sage: mi
    [4, 3, 5, 7, 137, 593, 24337, 25589, 3637793, 5733569]
    sage: x = 1
    sage: for m in mi:
    ....:     x = lcm(x, m)
    ....:     
    sage: x
    443208349730265573969192476820

That value of `m` is already greater than the upper bound for N! Therefore, we must have that in the next call to `crt()`, either `q=0` or `alpha=0`. Here's the relevant source code in `crt()`:

    g, alpha, beta = XGCD(m, n)  
    q, r = (b - a).quo_rem(g)


In particular, `XGCD()` calculates alpha and beta such that `g = gcd(m,n) = alpha*m + beta*n`. `m` is the `lcm` so far, which is co-prime to `n`, the next prime factor of the order of the elliptic curve E. So we know that `g=1` and can also confirm that alpha is not 0:

    sage: xgcd(443208349730265573969192476820, 106831998530025000830453)
    (1, -9154566621588952169298, 37979073879347959321206035237)

 So it turns out that `alpha = -9154566621588952169298.` Therefore we must have that `q=0`. But since `g=1`, then we must have that `b-a` equals 0, so `b=a`. `a` is the output from the previous step of the Chinese Remainder Theorem, which I already have. `b` is in fact the next value of `l[i]` in the Pohlig-Hellman code, so if I wanted to I now have enough information to solve the ECDLP for those other two factors! But it is enough for this problem to recognize that `a` cannot get larger in the final two passes of the Chinese Remainder Theorem, and hence the ultimate value of `n` must remain  249838002898687975937532407250. And that's the solution!

 ![solved.png](./solved.png)

 ## Conclusion

 The take-away from this problem is that when solving the Elliptic Curve Discrete Log Problem over an interval, Pollard's Kangaroo algorithm is not the only feasible approach. If the order of the curve is B-smooth where B is roughly less than 2^80, then the Pohlig-Hellman algorithm can quickly compute an answer. And even if the order of the curve is not B-smooth as in the case of the present problem, sometimes a combination of an elliptic curve that has an order with several small factors, along with an upper bound on the desired discrete log `n`, can enough to solve the ECDLP just by running the Pohlig-Hellman algorithm and feeding the solutions for the smaller factors of the order of the curve into the Chinese Remainder Theorem. I have no idea how often this last approach would work in the wild, and suspect that this was merely a contrived problem to motivate students to learn about elliptic curves, the Chinese Remainder Theorem, and the Pohlig-Hellman algorithm.
