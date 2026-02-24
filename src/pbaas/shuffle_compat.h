#ifndef VERUS_PBAAS_SHUFFLE_COMPAT_H
#define VERUS_PBAAS_SHUFFLE_COMPAT_H

#ifndef __GLIBCXX__

// Derived from: GCC libstdc++ <bits/uniform_int_dist.h> and <bits/stl_algo.h>
// Copyright (C) 2009-2023 Free Software Foundation, Inc.
// Licensed under: GPLv3 with GCC Runtime Library Exception 3.1
// See: https://www.gnu.org/licenses/gcc-exception-3.1.html

#include <iterator>
#include <utility>
#include <stdint.h>
template<typename IntType = int>
class gcc_uniform_int_distribution
{
public:
    typedef IntType result_type;

    gcc_uniform_int_distribution(IntType a, IntType b) : _M_a(a), _M_b(b) {}

    template<typename URBG>
    result_type operator()(URBG& g)
    {
        typedef typename URBG::result_type _Gresult_type;
        typedef typename std::make_unsigned<result_type>::type __utype;
        typedef typename std::make_unsigned<_Gresult_type>::type __ugtype;

        const __utype __urngrange = URBG::max() - URBG::min();
        const __utype __urange = __utype(_M_b) - __utype(_M_a);

        __utype __ret;

        if (__urngrange > __urange)
        {
            const __utype __uerange = __urange + 1;
            const __utype __scaling = __urngrange / __uerange;

            do
                __ret = __utype(g() - URBG::min()) / __scaling;
            while (__ret >= __uerange);
        }
        else if (__urngrange < __urange)
        {
            const __utype __uerngrange = __urngrange + 1;
            __utype __tmp;
            do
            {
                __tmp = (__uerngrange * operator()(g)) + (g() - URBG::min());
            }
            while (__tmp > __urange || __tmp < __uerngrange);
            __ret = __tmp;
        }
        else
        {
            __ret = g() - URBG::min();
        }

        return __ret + _M_a;
    }

private:
    result_type _M_a;
    result_type _M_b;
};

template<typename IntType, typename URBG>
std::pair<IntType, IntType> gen_two_uniform_ints(IntType b0, IntType b1, URBG& g)
{
    typedef typename std::make_unsigned<IntType>::type __utype;

    const __utype __range = (__utype(b0) * __utype(b1)) - 1;
    gcc_uniform_int_distribution<__utype> __d(0, __range);
    __utype __x = __d(g);

    return std::make_pair(__x / __utype(b1), __x % __utype(b1));
}

template<typename RandomAccessIterator, typename URBG>
void gcc_compatible_shuffle(RandomAccessIterator first, RandomAccessIterator last, URBG&& g)
{
    if (first == last) return;

    typedef typename std::iterator_traits<RandomAccessIterator>::difference_type difference_type;
    typedef typename std::make_unsigned<difference_type>::type __ud_type;

    const __ud_type __urange = __ud_type(last - first);

    if (__urange <= 1) return;

    typedef typename std::remove_reference<URBG>::type _Gen;
    typedef typename _Gen::result_type __uc_type;

    const __uc_type __urngrange = g.max() - g.min();

    if (__urngrange / __urange >= __urange)
    {
        RandomAccessIterator __i = first + 1;

        if ((__urange % 2) == 0)
        {
            gcc_uniform_int_distribution<__ud_type> __d(0, 1);
            std::iter_swap(__i++, first + __d(g));
        }
        while (__i != last)
        {
            const __ud_type __swap_range = __ud_type(__i - first) + 1;

            const std::pair<__ud_type, __ud_type> __pospos =
                gen_two_uniform_ints(__swap_range, __swap_range + 1, g);

            std::iter_swap(__i++, first + __pospos.first);
            std::iter_swap(__i++, first + __pospos.second);
        }
    }
    else
    {
        for (RandomAccessIterator __i = first + 1; __i != last; ++__i)
        {
            __ud_type __swap_range = __ud_type(__i - first);
            gcc_uniform_int_distribution<__ud_type> __d(0, __swap_range);
            std::iter_swap(__i, first + __d(g));
        }
    }
}

#endif // __GLIBCXX__

#endif // VERUS_PBAAS_SHUFFLE_COMPAT_H
